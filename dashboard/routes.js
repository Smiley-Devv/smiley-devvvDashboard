const path = require('path');
const express = require('express');
const bodyParser = require('body-parser');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const dns = require('dns');
const {
  PermissionsBitField,
  AuditLogEvent,
  AutoModerationRuleTriggerType,
  AutoModerationRuleEventType,
  AutoModerationActionType,
  AutoModerationRuleKeywordPresetType,
  EmbedBuilder,
  ActionRowBuilder,
  StringSelectMenuBuilder,
  StringSelectMenuOptionBuilder,
} = require('discord.js');

const Premium = require('../Schemas/premiumUserSchema');
const PremiumGuild = require('../Schemas/premiumGuildSchema');
const GuildBlacklist = require('../Schemas/guildBlacklistSchema');
const UserBlacklist = require('../Schemas/blacklistSchema');
const IpBlacklist = require('../Schemas/ipBlacklistSchema');
const VerifiedUser = require('../Schemas/verifiedUserSchema');
const AdminUser = require('../Schemas/adminUserSchema');
const UserAccount = require('../Schemas/userAccount');
const TwitchNotification = require('../Schemas/twitchSchema');
const YouTubeNotification = require('../Schemas/youtubeSchema');
const Warning = require('../Schemas/warnSchema');
const WelcomeMessage = require('../Schemas/welcomeMessageSchema');
const logSchema = require('../Schemas/logschema');
const TicketSetup = require('../Schemas/TicketSetup');
const ticketConfig = require('../ticketconfig');

module.exports = (app, client, passport) => {
  let maintenanceMode = false;

  const isOwnerOrAdmin = async (req, res, next) => {
    try {
      const uid = req.user?.id;
      if (!uid) return res.status(401).json({ error: 'Unauthorized' });
      if (uid === process.env.developerId) return next();
      const admin = await AdminUser.findOne({ userId: uid }).lean().catch(() => null);
      if (!admin) return res.status(403).json({ error: 'Access denied' });
      return next();
    } catch {
      return res.status(403).json({ error: 'Access denied' });
    }
  };

  // Middleware
  app.set('trust proxy', 1);
  app.use(
    helmet({
      contentSecurityPolicy: false,
      crossOriginEmbedderPolicy: false,
    }),
  );
  app.use(bodyParser.json({ limit: '250kb' }));
  app.use(bodyParser.urlencoded({ extended: true, limit: '250kb' }));

  app.use(async (req, res, next) => {
    try {
      const forwarded = req.headers['x-forwarded-for'];
      const ip = (Array.isArray(forwarded) ? forwarded[0] : (forwarded || '')).split(',')[0].trim() || req.ip;
      const found = await IpBlacklist.findOne({ ip });
      if (found) {
        return res.status(403).render('error', {
          title: 'Access Denied',
          message: 'Your IP is blacklisted.',
          layout: 'layout'
        });
      }
      next();
    } catch {
      next();
    }
  });

  app.use(async (req, res, next) => {
    if (req.path === '/vpn' || req.path === '/adblocker') return next();
    try {
      if (process.env.ENABLE_VPN_DETECT === 'false' || req.session?.dismissVpn === true) return next();
      const uid = req.session?.user?.id;
      if (uid) {
        const prefs = await UserAccount.findOne({ userId: uid }).lean().catch(() => null);
        if (prefs?.dismissVpn) return next();
      }
      const rawFwd = req.headers['x-forwarded-for'];
      const ip =
        (req.headers['cf-connecting-ip'] ||
         req.headers['x-real-ip'] ||
         (Array.isArray(rawFwd) ? rawFwd[0] : (rawFwd || ''))).toString().split(',')[0].trim() ||
        req.ip;
      const via = String(req.headers['via'] || '').toLowerCase();
      const markers = [
        'tor','mullvad','nordvpn','protonvpn','surfshark','windscribe','expressvpn','privateinternetaccess','hidemyass',
        'operavpn','surfeasy','hola','browsec','zenmate','hotspotshield','touchvpn','tunnelbear','privado','cyberghost','purevpn','ultravpn'
      ];
      if (via && markers.some(m => via.includes(m))) {
        return res.redirect('/vpn');
      }
      dns.reverse(ip, (err, hostnames) => {
        const h = (hostnames || []).join(' ').toLowerCase();
        if (!err && h && markers.some(m => h.includes(m))) {
          return res.redirect('/vpn');
        }
        next();
      });
    } catch {
      next();
    }
  });

  app.use((req, res, next) => {
    try {
      const u = req.session?.user;
      if (u?.id) {
        req.app.locals.activeUsers = req.app.locals.activeUsers || new Map();
        req.app.locals.activeUsers.set(u.id, { id: u.id, username: u.username, lastSeenAt: Date.now() });
        const cutoff = Date.now() - 30 * 60 * 1000;
        for (const [id, info] of req.app.locals.activeUsers) {
          if ((info.lastSeenAt || info.loggedInAt || 0) < cutoff) {
            req.app.locals.activeUsers.delete(id);
          }
        }
      }
    } catch {}
    next();
  });

  const rateLimitHandler = (req, res) => {
    const response = { error: 'Too many requests. Please slow down.' };
    if (req.originalUrl.startsWith('/api/')) {
      return res.status(429).json(response);
    }
    return res.status(429).render('error', {
      title: 'Too Many Requests',
      message: response.error,
      layout: 'layout'
    });
  };

  const apiLimiter = rateLimit({
    windowMs: 60 * 1000,
    legacyHeaders: false,
    standardHeaders: true,
    limit: 600, // allow more API calls per minute
    // Skip limiting for common read-only endpoints to support daily dashboard use
    skip: (req) => {
      if (req.method !== 'GET') return false;
      const url = req.originalUrl;
      const readWhitelist = [
        /^\/api\/guilds\/[^/]+\/channels/,
        /^\/api\/guilds\/[^/]+\/roles/,
        /^\/api\/guilds\/[^/]+\/categories/,
        /^\/api\/guilds\/[^/]+\/welcome$/,
        /^\/api\/guilds\/[^/]+\/logs$/,
        /^\/api\/guilds\/[^/]+\/twitch$/,
        /^\/api\/guilds\/[^/]+\/youtube$/,
        /^\/api\/guilds\/[^/]+\/modlogs$/,
        /^\/api\/guilds\/[^/]+\/automod$/
      ];
      return readWhitelist.some((re) => re.test(url));
    },
    handler: rateLimitHandler,
  });

  const actionLimiter = rateLimit({
    windowMs: 5 * 60 * 1000,
    legacyHeaders: false,
    standardHeaders: true,
    limit: 60, // more generous for moderation actions
    handler: rateLimitHandler,
  });

  const authLimiter = rateLimit({
    windowMs: 5 * 60 * 1000,
    legacyHeaders: false,
    standardHeaders: true,
    limit: 30, // allow more login/callback attempts per 5 minutes
    handler: rateLimitHandler,
  });

  // Softer limiter for moderation logs endpoint to prevent abuse but allow daily browsing
  const modLogsLimiter = rateLimit({
    windowMs: 60 * 1000,
    legacyHeaders: false,
    standardHeaders: true,
    limit: 120,
    handler: rateLimitHandler,
  });

  app.use('/api/', apiLimiter);
  app.use(
    ['/api/guilds/:guildId/kick', '/api/guilds/:guildId/ban', '/api/guilds/:guildId/warn'],
    actionLimiter,
  );
  app.use('/api/guilds/:guildId/modlogs', modLogsLimiter);
  app.use(['/login', '/callback'], authLimiter);
  
  // Serve static files from the public directory
  app.use(express.static(path.join(__dirname, 'public')));

  const isAuthenticated = (req, res, next) => {
    if (req.isAuthenticated()) return next();
    res.redirect('/login');
  };

  // Home/Dashboard
  app.get('/', (req, res) => {
    res.render('index', {
      title: 'Bot Dashboard',
      user: req.session.user,
      layout: 'layout',
      stats: {
        guilds: client.guilds.cache.size,
        users: client.guilds.cache.reduce((a, b) => a + b.memberCount, 0),
        commands: client.commands.size,
      },
    });
  });

  // Premium plans
  app.get('/premium', async (req, res) => {
    const plans = [
      { name: 'Basic', price: 5, features: ['Feature 1', 'Feature 2'] },
      { name: 'Pro', price: 10, features: ['All Basic features', 'Feature 3', 'Feature 4'] },
      { name: 'Ultimate', price: 20, features: ['All Pro features', 'Feature 5', 'Priority support'] },
    ];
    let managedGuilds = [];
    try {
      const sessionUser = req.session.user;
      if (sessionUser?.guilds?.length) {
        managedGuilds = sessionUser.guilds
          .filter(g => client.guilds.cache.has(g.id) && ((g.permissions & 0x20) === 0x20))
          .map(g => ({ id: g.id, name: g.name }));
      }
    } catch {}
    res.render('premium', { title: 'Premium Plans', plans, user: req.session.user, managedGuilds, layout: 'layout' });
  });

  // Terms / Privacy
  app.get('/tos', (req, res) => res.render('tos', { title: 'Terms of Service', date: 'November 20, 2025', layout: 'layout' }));
  app.get('/privacy', (req, res) => res.render('privacy', { title: 'Privacy Policy', date: 'November 20, 2025', layout: 'layout' }));

  // OAuth
  app.get('/login', passport.authenticate('discord'));
  app.get('/callback', passport.authenticate('discord', { failureRedirect: '/' }), (req, res) => {
    req.session.user = req.user;
    try {
      req.app.locals.activeUsers = req.app.locals.activeUsers || new Map();
      const u = req.user || {};
      req.app.locals.activeUsers.set(u.id, { id: u.id, username: u.username, loggedInAt: Date.now() });
    } catch {}
    res.redirect('/');
  });
  app.get('/logout', (req, res) => {
    try {
      req.app.locals.activeUsers = req.app.locals.activeUsers || new Map();
      const id = req.user?.id || req.session?.user?.id;
      if (id) req.app.locals.activeUsers.delete(id);
    } catch {}
    req.logout(() => res.redirect('/'));
  });

  app.get('/adblocker', (req, res) => {
    res.render('Adblocker', { title: 'Ad Blocker Detected', user: req.session.user, layout: 'layout' });
  });

  app.get('/vpn', (req, res) => {
    res.render('Vpn', { title: 'VPN Or Proxy Detected', user: req.session.user, layout: 'layout' });
  });

  app.get('/ack/vpn', (req, res) => {
    try {
      req.session.dismissVpn = true;
      if (req.user?.id) {
        UserAccount.findOneAndUpdate(
          { userId: req.user.id },
          { userId: req.user.id, dismissVpn: true },
          { upsert: true }
        ).catch(() => {});
      }
    } catch {}
    res.redirect('/');
  });

  app.get('/ack/adblock', (req, res) => {
    try {
      req.session.dismissAdblock = true;
      if (req.user?.id) {
        UserAccount.findOneAndUpdate(
          { userId: req.user.id },
          { userId: req.user.id, dismissAdblock: true },
          { upsert: true }
        ).catch(() => {});
      }
    } catch {}
    res.redirect('/');
  });

  // Profile
  app.get('/profile', isAuthenticated, async (req, res) => {
    try {
      const premiumUser = await Premium.findOne({ id: req.user.id });
      const userGuilds = req.user.guilds.filter(guild =>
        client.guilds.cache.has(guild.id) &&
        (guild.permissions & 0x20) === 0x20
      );
      res.render('profile', { title: 'User Profile', user: req.user, premium: premiumUser, guilds: userGuilds, layout: 'layout' });
    } catch (err) {
      console.error(err);
      res.status(500).send('Internal Server Error');
    }
  });

  // Premium payment success
  app.get('/premium/success', isAuthenticated, async (req, res) => {
    try {
      const { plan = null, guildId = null } = req.query;
      res.render('premiumSuccess', { title: 'Payment Successful', client, plan, guildId, user: req.session.user, layout: 'layout' });
    } catch (err) {
      console.error(err);
      res.status(500).send('Internal Server Error');
    }
  });

  // Subscribe to user premium
  app.post('/premium/subscribe', isAuthenticated, async (req, res) => {
    try {
      const { plan = null } = req.body;
      if (!plan) return res.status(400).send('Plan is required');
      const expiresAt = new Date();
      expiresAt.setMonth(expiresAt.getMonth() + 1);
      await Premium.findOneAndUpdate(
        { id: req.user.id },
        { id: req.user.id, isPremium: true, premium: { plan, expiresAt, redeemedAt: new Date(), redeemedBy: [req.user.id] } },
        { upsert: true, new: true }
      );
      res.redirect('/profile');
    } catch (err) {
      console.error(err);
      res.status(500).send('Internal Server Error');
    }
  });

  // Subscribe to guild premium
  app.post('/guild/:id/premium/subscribe', isAuthenticated, async (req, res) => {
    try {
      const guild = client.guilds.cache.get(req.params.id);
      if (!guild) return res.status(404).send('Guild not found');
      const member = await guild.members.fetch(req.user.id);
      if (!member.permissions.has('MANAGE_GUILD')) return res.status(403).send('You do not have permission');

      const { plan = null } = req.body;
      if (!plan) return res.status(400).send('Plan is required');
      const expiresAt = new Date();
      expiresAt.setMonth(expiresAt.getMonth() + 1);

      const updated = await PremiumGuild.findOneAndUpdate(
        { id: req.params.id },
        { id: req.params.id, isPremiumGuild: true, premium: { plan, expiresAt, redeemedAt: new Date(), redeemedBy: [req.user.id] } },
        { upsert: true, new: true }
      );
      client.premiumGuilds.set(req.params.id, true);
      res.redirect(`/guild/${req.params.id}`);
    } catch (err) {
      console.error(err);
      res.status(500).send('Internal Server Error');
    }
  });

  app.post('/premium/deactivate', isAuthenticated, async (req, res) => {
    try {
      await Premium.findOneAndUpdate(
        { id: req.user.id },
        { isPremium: false, 'premium.expiresAt': null, 'premium.plan': null },
        { new: true }
      );
      res.redirect('/profile');
    } catch (err) {
      console.error(err);
      res.status(500).send('Internal Server Error');
    }
  });

  app.post('/guild/:id/premium/deactivate', isAuthenticated, async (req, res) => {
    try {
      const guild = client.guilds.cache.get(req.params.id);
      if (!guild) return res.status(404).send('Guild not found');
      const member = await guild.members.fetch(req.user.id);
      if (!member.permissions.has('MANAGE_GUILD')) return res.status(403).send('You do not have permission');

      await PremiumGuild.findOneAndUpdate(
        { id: req.params.id },
        { isPremiumGuild: false, 'premium.expiresAt': null, 'premium.plan': null },
        { new: true }
      );
      client.premiumGuilds.delete(req.params.id);
      res.redirect(`/guild/${req.params.id}`);
    } catch (err) {
      console.error(err);
      res.status(500).send('Internal Server Error');
    }
  });

  app.get('/api/premium/status', isAuthenticated, async (req, res) => {
    try {
      const doc = await Premium.findOne({ id: req.user.id });
      res.json({ success: true, premium: doc || null });
    } catch (err) {
      console.error(err);
      res.status(500).json({ error: 'Internal Server Error' });
    }
  });

  app.get('/api/guilds/:id/premium/status', isAuthenticated, async (req, res) => {
    try {
      const guild = client.guilds.cache.get(req.params.id);
      if (!guild) return res.status(404).json({ error: 'Guild not found' });
      const member = await guild.members.fetch(req.user.id).catch(() => null);
      if (!member || !member.permissions.has('MANAGE_GUILD')) return res.status(403).json({ error: 'You do not have permission' });
      const doc = await PremiumGuild.findOne({ id: req.params.id });
      res.json({ success: true, premiumGuild: doc || null, cached: client.premiumGuilds.get(req.params.id) === true });
    } catch (err) {
      console.error(err);
      res.status(500).json({ error: 'Internal Server Error' });
    }
  });

  // API: Get guild channels
  app.get('/api/guilds/:guildId/channels', isAuthenticated, async (req, res) => {
    try {
      console.log(`[Channels] Fetching channels for guild: ${req.params.guildId}`);
      
      // Try to get the guild from cache first
      let guild = client.guilds.cache.get(req.params.guildId);
      
      // If guild not in cache, try to fetch it
      if (!guild) {
        console.log('[Channels] Guild not in cache, fetching...');
        try {
          guild = await client.guilds.fetch(req.params.guildId);
        } catch (error) {
          console.error('[Channels] Error fetching guild:', error);
          return res.status(404).json({ error: 'Guild not found' });
        }
      }
      console.log(`[Channels] Found guild: ${guild.name} (${guild.id})`);
      
      // Get all text channels the bot can see
      console.log('[Channels] Fetching text channels...');
      const channels = await guild.channels.fetch();
      
      // Get bot member for permission checks
      const botMember = guild.members.me || await guild.members.fetchMe();
      console.log(`[Channels] Bot's roles:`, botMember.roles.cache.map(r => r.name));
      
      // Process channels
      const textChannels = [];
      
      for (const channel of channels.values()) {
        try {
          // Only include text channels
          if (channel.type !== 0) continue;
          
          // Check if bot has permission to view and send messages in this channel
          const permissions = channel.permissionsFor(botMember);
          const canView = permissions.has('VIEW_CHANNEL') || permissions.has('READ_MESSAGES');
          const canSend = permissions.has('SEND_MESSAGES');
          
          if (canView && canSend) {
            textChannels.push({
              id: channel.id,
              name: channel.name,
              type: channel.type,
              position: channel.position,
              parent: channel.parent ? {
                id: channel.parent.id,
                name: channel.parent.name
              } : null
            });
          }
        } catch (error) {
          console.error(`[Channels] Error processing channel ${channel?.id}:`, error);
        }
      }
      
      // Sort channels by position
      textChannels.sort((a, b) => a.position - b.position);
      
      console.log(`[Channels] Found ${textChannels.length} accessible text channels`);
      return res.json(textChannels);
    } catch (error) {
      console.error('[Channels] Error:', error);
      res.status(500).json({ 
        error: 'Failed to fetch channels',
        details: error.message,
        stack: process.env.NODE_ENV === 'development' ? error.stack : undefined
      });
    }
  });
// Get all Twitch notifications for a guild
  app.get('/api/guilds/:guildId/twitch', isAuthenticated, async (req, res) => {
  try {
    const guild = client.guilds.cache.get(req.params.guildId);
    if (!guild) {
      console.error('Guild not found:', req.params.guildId);
      return res.status(404).json({ error: 'Guild not found' });
    }
    
    const member = await guild.members.fetch(req.user.id).catch(() => null);
    if (!member || !member.permissions.has('MANAGE_GUILD')) {
      console.error('User lacks MANAGE_GUILD permission:', req.user.id);
      return res.status(403).json({ error: 'Missing permissions' });
    }

    const notifications = await TwitchNotification.find({ Guild: guild.id });
    
    // Add channel names to the response
    const notificationsWithChannelNames = await Promise.all(notifications.map(async (notification) => {
      const channel = guild.channels.cache.get(notification.Channel);
      return {
        ...notification.toObject(),
        channelName: channel?.name || 'deleted-channel',
        _id: notification._id.toString()
      };
    }));
    
    console.log(`Found ${notificationsWithChannelNames.length} notifications for guild ${guild.id}`);
    res.json(notificationsWithChannelNames);
    
  } catch (error) {
    console.error('Error fetching Twitch notifications:', error);
    res.status(500).json({ 
      error: 'Internal server error',
      message: error.message 
    });
  }
});

// Add Twitch notification
app.post('/api/guilds/:guildId/twitch', isAuthenticated, async (req, res) => {
  const { Channel, Streamer, Message } = req.body;
  const guildId = req.params.guildId;
  
  try {
    const guild = client.guilds.cache.get(guildId);
    if (!guild) {
      console.error('Guild not found:', guildId);
      return res.status(404).json({ error: 'Guild not found' });
    }
    
    const member = await guild.members.fetch(req.user.id).catch(() => null);
    if (!member || !member.permissions.has('MANAGE_GUILD')) {
      console.error('User lacks MANAGE_GUILD permission:', req.user.id);
      return res.status(403).json({ error: 'Missing permissions' });
    }

    if (!Channel || !Streamer) {
      console.error('Missing required fields:', { Channel, Streamer });
      return res.status(400).json({ error: 'Channel and Streamer are required' });
    }

    const notification = new TwitchNotification({
      Guild: guildId,
      Channel,
      Streamer: Streamer.toLowerCase(),
      Message: Message || `{streamer} is now live! {url}`
    });

    console.log('Saving notification:', notification);
    await notification.save();
    
    // Send back the saved notification with channel info for the UI
    const channel = guild.channels.cache.get(Channel);
    const responseData = {
      ...notification.toObject(),
      channelName: channel?.name || 'unknown'
    };
    
    console.log('Notification saved successfully:', responseData);
    res.status(201).json(responseData);
    
  } catch (error) {
    console.error('Error in Twitch notification route:', error);
    res.status(500).json({ 
      error: 'Internal server error',
      message: error.message
    });
  }
});

// Test Twitch notification
app.post('/api/guilds/:guildId/twitch/:id/test', isAuthenticated, async (req, res) => {
  try {
    const notification = await TwitchNotification.findById(req.params.id);
    if (!notification) {
      return res.status(404).json({ error: 'Notification not found' });
    }
    
    const guild = client.guilds.cache.get(req.params.guildId);
    if (!guild) {
      return res.status(404).json({ error: 'Guild not found' });
    }
    
    const channel = guild.channels.cache.get(notification.Channel);
    if (!channel) {
      return res.status(400).json({ error: 'Channel not found' });
    }
    
    const testMessage = notification.Message
      .replace('{streamer}', notification.Streamer)
      .replace('{url}', `https://twitch.tv/${notification.Streamer}`)
      .replace('{title}', 'Test Stream Title')
      .replace('{game}', 'Test Game');
    
    await channel.send(`🔔 **Twitch Notification Test**\n${testMessage}`);
    
    res.json({ success: true });
  } catch (error) {
    console.error('Error sending test notification:', error);
    res.status(500).json({ 
      error: 'Failed to send test notification',
      message: error.message
    });
  }
});

// Delete Twitch notification
app.delete('/api/guilds/:guildId/twitch/:id', isAuthenticated, async (req, res) => {
  try {
    const guild = client.guilds.cache.get(req.params.guildId);
    if (!guild) {
      console.error('Guild not found:', req.params.guildId);
      return res.status(404).json({ error: 'Guild not found' });
    }
    
    const member = await guild.members.fetch(req.user.id).catch(() => null);
    if (!member || !member.permissions.has('MANAGE_GUILD')) {
      console.error('User lacks MANAGE_GUILD permission:', req.user.id);
      return res.status(403).json({ error: 'Missing permissions' });
    }

    const result = await TwitchNotification.deleteOne({ _id: req.params.id, Guild: guild.id });
    if (result.deletedCount === 0) {
      console.error('Notification not found:', req.params.id);
      return res.status(404).json({ error: 'Notification not found' });
    }
    
    console.log('Notification deleted successfully:', req.params.id);
    res.status(200).json({ success: true });
    
  } catch (error) {
    console.error('Error deleting Twitch notification:', error);
    res.status(500).json({ 
      error: 'Internal server error',
      message: error.message
    });
  }
});

  // API: YouTube Notifications
  app.get('/api/guilds/:guildId/youtube', isAuthenticated, async (req, res) => {
    try {
      const guild = client.guilds.cache.get(req.params.guildId);
      if (!guild) return res.status(404).json({ error: 'Guild not found' });
      
      const member = await guild.members.fetch(req.user.id).catch(() => null);
      if (!member || !member.permissions.has('MANAGE_GUILD')) {
        return res.status(403).json({ error: 'Missing permissions' });
      }

      const notifications = await YouTubeNotification.find({ Guild: guild.id });
      const withChannelNames = await Promise.all(
        notifications.map(async (n) => {
          const channel = guild.channels.cache.get(n.Channel);
          return {
            ...n.toObject(),
            channelName: channel?.name || 'deleted-channel',
            _id: n._id.toString(),
          };
        })
      );
      res.json(withChannelNames);
    } catch (error) {
      console.error('Error fetching YouTube notifications:', error);
      res.status(500).json({ error: 'Internal server error' });
    }
  });

  app.post('/api/guilds/:guildId/youtube', isAuthenticated, async (req, res) => {
    const { channelId, youtubeChannel, message } = req.body;
    
    try {
      const guild = client.guilds.cache.get(req.params.guildId);
      if (!guild) return res.status(404).json({ error: 'Guild not found' });
      
      const member = await guild.members.fetch(req.user.id).catch(() => null);
      if (!member || !member.permissions.has('MANAGE_GUILD')) {
        return res.status(403).json({ error: 'Missing permissions' });
      }

      // Get the next setup number
      const count = await YouTubeNotification.countDocuments({ Guild: guild.id });
      
      if (!channelId || !youtubeChannel) {
        return res.status(400).json({ error: 'Channel to notify and YouTube channel are required' });
      }
      const normalizedUrl =
        youtubeChannel.startsWith('http')
          ? youtubeChannel
          : youtubeChannel.startsWith('@')
          ? `https://www.youtube.com/${youtubeChannel}`
          : `https://www.youtube.com/@${youtubeChannel}`;
      const notification = new YouTubeNotification({
        Guild: guild.id,
        Channel: channelId,
        YouTubeChannel: normalizedUrl,
        Message: message || `New video from {channel}: {title}\n{url}`,
        SetupNumber: count + 1,
      });

      await notification.save();
      const channel = guild.channels.cache.get(channelId);
      const responseData = {
        ...notification.toObject(),
        channelName: channel?.name || 'unknown',
      };
      res.status(201).json(responseData);
    } catch (error) {
      console.error('Error creating YouTube notification:', error);
      res.status(500).json({ error: 'Internal server error' });
    }
  });
//
// Add these routes to your existing routes.js file, after your existing routes

// Get server members
app.get('/api/guilds/:guildId/members', isAuthenticated, async (req, res) => {
    try {
        const guild = client.guilds.cache.get(req.params.guildId);
        if (!guild) return res.status(404).json({ error: 'Guild not found' });
        
        const member = await guild.members.fetch(req.user.id).catch(() => null);
        if (!member) return res.status(403).json({ error: 'You need to be a member of this server' });
        
        if (!member.permissions.any([
            PermissionsBitField.Flags.KickMembers,
            PermissionsBitField.Flags.BanMembers,
            PermissionsBitField.Flags.ManageGuild,
            PermissionsBitField.Flags.Administrator
        ])) {
            return res.status(403).json({ error: 'You do not have permission to view members' });
        }
        
        let membersCollection;
        try {
            membersCollection = await guild.members.list({ limit: 1000 });
        } catch (fetchError) {
            console.warn('Error listing guild members (falling back to cache):', fetchError);
            membersCollection = guild.members.cache;
        }
        
        const members = (membersCollection.size ? membersCollection : guild.members.cache)
            .filter(m => !m.user.bot)
            .sort((a, b) => a.displayName.localeCompare(b.displayName))
            .map(member => ({
                id: member.id,
                tag: member.user.tag,
                displayName: member.displayName,
                avatar: member.user.displayAvatarURL({ dynamic: true })
            }));

        res.json(members);
    } catch (error) {
        console.error('Error fetching members:', error);
        res.status(500).json({ error: 'Failed to fetch members' });
    }
});

// Kick member
app.post('/api/guilds/:guildId/kick', isAuthenticated, async (req, res) => {
    try {
        const { userId, reason } = req.body;
        const guild = client.guilds.cache.get(req.params.guildId);
        
        if (!guild) return res.status(404).json({ error: 'Guild not found' });
        
        const member = await guild.members.fetch(req.user.id).catch(() => null);
        if (!member) return res.status(403).json({ error: 'You need to be a member of this server' });
        
        if (!member.permissions.any([PermissionsBitField.Flags.KickMembers, PermissionsBitField.Flags.ManageGuild, PermissionsBitField.Flags.Administrator])) {
            return res.status(403).json({ error: 'You do not have permission to kick members' });
        }
        
        const targetMember = await guild.members.fetch(userId).catch(() => null);
        if (!targetMember) return res.status(404).json({ error: 'Member not found' });
        
        if (targetMember.roles.highest.position >= member.roles.highest.position && member.id !== guild.ownerId) {
            return res.status(403).json({ error: 'You cannot kick this member due to role hierarchy' });
        }
        
        await targetMember.kick(reason || 'No reason provided');
        
        res.json({ 
            success: true,
            message: `Successfully kicked ${targetMember.user.tag}`
        });
    } catch (error) {
        console.error('Error kicking member:', error);
        res.status(500).json({ error: error.message || 'Failed to kick member' });
    }
});

// Ban member
app.post('/api/guilds/:guildId/ban', isAuthenticated, async (req, res) => {
    try {
        const { userId, reason, deleteMessages } = req.body;
        const guild = client.guilds.cache.get(req.params.guildId);
        
        if (!guild) return res.status(404).json({ error: 'Guild not found' });
        
        const member = await guild.members.fetch(req.user.id).catch(() => null);
        if (!member) return res.status(403).json({ error: 'You need to be a member of this server' });
        
        if (!member.permissions.any([PermissionsBitField.Flags.BanMembers, PermissionsBitField.Flags.Administrator])) {
            return res.status(403).json({ error: 'You do not have permission to ban members' });
        }
        
        const targetUser = await client.users.fetch(userId).catch(() => null);
        if (!targetUser) return res.status(404).json({ error: 'User not found' });
        
        const banList = await guild.bans.fetch();
        if (banList.has(userId)) {
            return res.status(400).json({ error: 'This user is already banned' });
        }
        
        const targetMember = await guild.members.fetch(userId).catch(() => null);
        
        if (targetMember) {
            if (targetMember.roles.highest.position >= member.roles.highest.position && member.id !== guild.ownerId) {
                return res.status(403).json({ error: 'You cannot ban this member due to role hierarchy' });
            }
        }
        
        await guild.members.ban(userId, {
            reason: reason || 'No reason provided',
            deleteMessageDays: deleteMessages ? 7 : 0
        });
        
        res.json({ 
            success: true,
            message: `Successfully banned ${targetUser.tag}`
        });
    } catch (error) {
        console.error('Error banning member:', error);
        res.status(500).json({ error: error.message || 'Failed to ban member' });
    }
});

// Warn member
app.post('/api/guilds/:guildId/warn', isAuthenticated, async (req, res) => {
    try {
        const { userId, reason } = req.body;
        const guild = client.guilds.cache.get(req.params.guildId);
        
        if (!guild) return res.status(404).json({ error: 'Guild not found' });
        
        const member = await guild.members.fetch(req.user.id).catch(() => null);
        if (!member) return res.status(403).json({ error: 'You need to be a member of this server' });
        
        if (!member.permissions.any([PermissionsBitField.Flags.KickMembers, PermissionsBitField.Flags.ManageGuild])) {
            return res.status(403).json({ error: 'You do not have permission to warn members' });
        }
        
        const targetMember = await guild.members.fetch(userId).catch(() => null);
        if (!targetMember) return res.status(404).json({ error: 'Member not found' });
        
        if (targetMember.roles.highest.position >= member.roles.highest.position && member.id !== guild.ownerId) {
            return res.status(403).json({ error: 'You cannot warn this member due to role hierarchy' });
        }
        
        const warning = new Warning({
            guildId: guild.id,
            userId: targetMember.id,
            moderatorId: member.id,
            reason: reason || 'No reason provided',
            timestamp: Date.now()
        });
        
        await warning.save();
        
        try {
            await targetMember.send(`You have been warned in **${guild.name}**\n**Reason:** ${reason || 'No reason provided'}\n**Moderator:** ${member.user.tag}`);
        } catch (dmError) {
            console.error('Failed to send DM to user:', dmError);
        }
        
        res.json({ 
            success: true,
            message: `Successfully warned ${targetMember.user.tag}`
        });
    } catch (error) {
        console.error('Error warning member:', error);
        res.status(500).json({ error: error.message || 'Failed to warn member' });
    }
});

// Get member warnings
  app.get('/api/guilds/:guildId/warnings/:userId', isAuthenticated, async (req, res) => {
    try {
        const { guildId, userId } = req.params;
        const guild = client.guilds.cache.get(guildId);
        
        if (!guild) return res.status(404).json({ error: 'Guild not found' });
        
        const member = await guild.members.fetch(req.user.id).catch(() => null);
        if (!member) return res.status(403).json({ error: 'You need to be a member of this server' });
        
        if (userId !== member.id && !member.permissions.any([PermissionsBitField.Flags.KickMembers, PermissionsBitField.Flags.ManageGuild, PermissionsBitField.Flags.Administrator])) {
            return res.status(403).json({ error: 'You do not have permission to view this member\'s warnings' });
        }
        
        const warnings = await Warning.find({
            guildId,
            userId
        }).sort({ timestamp: -1 });
        
        res.json({ 
            success: true,
            warnings
        });
    } catch (error) {
        console.error('Error fetching warnings:', error);
        res.status(500).json({ error: error.message || 'Failed to fetch warnings' });
    }
});

//
  app.delete('/api/guilds/:guildId/youtube/:id', isAuthenticated, async (req, res) => {
    try {
      const guild = client.guilds.cache.get(req.params.guildId);
      if (!guild) return res.status(404).json({ error: 'Guild not found' });
      
      const member = await guild.members.fetch(req.user.id).catch(() => null);
      if (!member || !member.permissions.has('MANAGE_GUILD')) {
        return res.status(403).json({ error: 'Missing permissions' });
      }

      const result = await YouTubeNotification.deleteOne({ _id: req.params.id, Guild: guild.id });
      if (result.deletedCount === 0) {
        return res.status(404).json({ error: 'Notification not found' });
      }
      
      res.status(200).json({ success: true });
    } catch (error) {
      console.error('Error deleting YouTube notification:', error);
      res.status(500).json({ error: 'Internal server error' });
    }
  });

  app.get('/api/guilds/:guildId/modlogs', isAuthenticated, async (req, res) => {
    try {
      const guild = client.guilds.cache.get(req.params.guildId);
      if (!guild) return res.status(404).json({ error: 'Guild not found' });
      const member = await guild.members.fetch(req.user.id).catch(() => null);
      if (!member) return res.status(403).json({ error: 'You need to be a member of this server' });
      const allowed = member.permissions.any([
        PermissionsBitField.Flags.KickMembers,
        PermissionsBitField.Flags.BanMembers,
        PermissionsBitField.Flags.ManageGuild,
        PermissionsBitField.Flags.Administrator
      ]);
      if (!allowed) return res.status(403).json({ error: 'Missing permissions' });
      const type = (req.query.type || 'all').toLowerCase();
      const limit = Math.min(parseInt(req.query.limit) || 10, 50);
      const offset = Math.max(parseInt(req.query.offset) || 0, 0);
      const actions = [];
      if (type === 'all' || type === 'kick') {
        const logs = await guild.fetchAuditLogs({ type: AuditLogEvent.MemberKick, limit: limit + offset });
        const entries = Array.from(logs.entries.values()).slice(offset, offset + limit);
        for (const e of entries) {
          actions.push({
            type: 'kick',
            userId: e.target?.id || '',
            userTag: e.target?.tag || e.target?.username || '',
            moderatorId: e.executor?.id || '',
            moderatorTag: e.executor?.tag || e.executor?.username || '',
            reason: e.reason || '',
            date: e.createdTimestamp || Date.now()
          });
        }
      }
      if (type === 'all' || type === 'ban') {
        const logs = await guild.fetchAuditLogs({ type: AuditLogEvent.MemberBanAdd, limit: limit + offset });
        const entries = Array.from(logs.entries.values()).slice(offset, offset + limit);
        for (const e of entries) {
          actions.push({
            type: 'ban',
            userId: e.target?.id || '',
            userTag: e.target?.tag || e.target?.username || '',
            moderatorId: e.executor?.id || '',
            moderatorTag: e.executor?.tag || e.executor?.username || '',
            reason: e.reason || '',
            date: e.createdTimestamp || Date.now()
          });
        }
      }
      if (type === 'all' || type === 'warn') {
        const warns = await Warning.find({ GuildID: guild.id }).sort({ _id: -1 }).limit(limit + offset);
        let index = 0;
        for (const doc of warns) {
          for (const w of (doc.Content || [])) {
            if (index >= offset && actions.length < limit) {
              actions.push({
                type: 'warn',
                userId: doc.UserID || '',
                userTag: doc.UserTag || '',
                moderatorId: w.ExecuterId || '',
                moderatorTag: w.ExecuterTag || '',
                reason: w.Reason || '',
                date: w.Date || new Date().toLocaleString()
              });
            }
            index++;
            if (actions.length >= limit) break;
          }
          if (actions.length >= limit) break;
        }
      }
      actions.sort((a, b) => new Date(b.date).valueOf() - new Date(a.date).valueOf());
      res.json({ success: true, actions, count: actions.length });
    } catch (error) {
      console.error('Error fetching moderation logs:', error);
      res.status(500).json({ error: 'Failed to fetch moderation logs' });
    }
  });

  app.get('/api/guilds/:guildId/automod', isAuthenticated, async (req, res) => {
    try {
      const guild = client.guilds.cache.get(req.params.guildId);
      if (!guild) return res.status(404).json({ error: 'Guild not found' });
      const member = await guild.members.fetch(req.user.id).catch(() => null);
      if (!member || !member.permissions.has(PermissionsBitField.Flags.ManageGuild)) {
        return res.status(403).json({ error: 'Missing permissions' });
      }
      await guild.autoModerationRules.fetch();
      const rules = Array.from(guild.autoModerationRules.cache.values());
      const linkPatterns = [
        "http[s]?://",
        "www\\.",
        "\\.com",
        "\\.net",
        "\\.org",
        "discord\\.gg",
        "discord\\.com/invite",
        "t\\.me",
        "instagram\\.com",
        "youtu(be\\.com|\\.be)"
      ];
      const flaggedWords = rules.find(r => r.enabled && r.triggerType === AutoModerationRuleTriggerType.KeywordPreset);
      const spamMessages = rules.find(r => r.enabled && r.triggerType === AutoModerationRuleTriggerType.Spam);
      const mentionSpam = rules.find(r => r.enabled && r.triggerType === AutoModerationRuleTriggerType.MentionSpam);
      const keywordRule = rules.find(
        r =>
          r.enabled &&
          r.triggerType === AutoModerationRuleTriggerType.Keyword &&
          r.triggerMetadata?.keywordFilter &&
          r.triggerMetadata.keywordFilter.length > 0
      );
      const antiLink = rules.find(
        r =>
          r.enabled &&
          r.triggerType === AutoModerationRuleTriggerType.Keyword &&
          Array.isArray(r.triggerMetadata?.regexPatterns) &&
          r.triggerMetadata.regexPatterns.some(p => linkPatterns.includes(p))
      );
      res.json({
        flaggedWords: !!flaggedWords,
        spamMessages: !!spamMessages,
        antiLink: !!antiLink,
        mentionSpam: {
          enabled: !!mentionSpam,
          limit: mentionSpam?.triggerMetadata?.mentionTotalLimit ?? null
        },
        keyword: {
          enabled: !!keywordRule,
          words: keywordRule?.triggerMetadata?.keywordFilter ?? []
        }
      });
    } catch (error) {
      console.error('Error fetching automod settings:', error);
      res.status(500).json({ error: 'Failed to fetch automod settings' });
    }
  });

  app.post('/api/guilds/:guildId/automod/enable', isAuthenticated, async (req, res) => {
    try {
      const guild = client.guilds.cache.get(req.params.guildId);
      if (!guild) return res.status(404).json({ error: 'Guild not found' });
      const member = await guild.members.fetch(req.user.id).catch(() => null);
      if (!member || !member.permissions.has(PermissionsBitField.Flags.ManageGuild)) {
        return res.status(403).json({ error: 'Missing permissions' });
      }
      const { type, number, word } = req.body;
      await guild.autoModerationRules.fetch();
      const existing = Array.from(guild.autoModerationRules.cache.values());
      const hasPreset = existing.find(r => r.triggerType === AutoModerationRuleTriggerType.KeywordPreset && r.enabled);
      const hasSpam = existing.find(r => r.triggerType === AutoModerationRuleTriggerType.Spam && r.enabled);
      const hasMention = existing.find(
        r =>
          r.triggerType === AutoModerationRuleTriggerType.MentionSpam &&
          r.enabled &&
          (!number || r.triggerMetadata?.mentionTotalLimit === Number(number))
      );
      const hasKeyword = existing.find(
        r =>
          r.triggerType === AutoModerationRuleTriggerType.Keyword &&
          r.enabled &&
          r.triggerMetadata?.keywordFilter &&
          word &&
          r.triggerMetadata.keywordFilter.map(w => String(w).toLowerCase()).includes(String(word).toLowerCase())
      );
      const linkPatterns = [
        "http[s]?://",
        "www\\.",
        "\\.com",
        "\\.net",
        "\\.org",
        "discord\\.gg",
        "discord\\.com/invite",
        "t\\.me",
        "instagram\\.com",
        "youtu(be\\.com|\\.be)"
      ];
      const hasAntiLink = existing.find(
        r =>
          r.triggerType === AutoModerationRuleTriggerType.Keyword &&
          r.enabled &&
          Array.isArray(r.triggerMetadata?.regexPatterns) &&
          r.triggerMetadata.regexPatterns.some(p => linkPatterns.includes(p))
      );
      if (type === 'flagged-words' && hasPreset) return res.status(400).json({ error: 'Flagged words already enabled' });
      if (type === 'spam-messages' && hasSpam) return res.status(400).json({ error: 'Spam messages already enabled' });
      if (type === 'mention-spam' && hasMention) return res.status(400).json({ error: 'Mention spam with this limit already enabled' });
      if (type === 'keyword' && hasKeyword) return res.status(400).json({ error: 'Keyword already blocked' });
      if (type === 'anti-link' && hasAntiLink) return res.status(400).json({ error: 'Anti-link already enabled' });
      let createPayload = null;
      if (type === 'flagged-words') {
        createPayload = {
          name: 'AutoMod: Profanity Filter',
          creatorId: client.user.id,
          enabled: true,
          eventType: AutoModerationRuleEventType.MessageSend,
          triggerType: AutoModerationRuleTriggerType.KeywordPreset,
          triggerMetadata: {
            presets: [
              AutoModerationRuleKeywordPresetType.Profanity,
              AutoModerationRuleKeywordPresetType.SexualContent,
              AutoModerationRuleKeywordPresetType.Slurs,
            ],
          },
          actions: [{ type: AutoModerationActionType.BlockMessage }]
        };
      } else if (type === 'spam-messages') {
        createPayload = {
          name: 'AutoMod: Spam Filter',
          creatorId: client.user.id,
          enabled: true,
          eventType: AutoModerationRuleEventType.MessageSend,
          triggerType: AutoModerationRuleTriggerType.Spam,
          triggerMetadata: {},
          actions: [{ type: AutoModerationActionType.BlockMessage }]
        };
      } else if (type === 'mention-spam') {
        if (!number || Number.isNaN(Number(number))) return res.status(400).json({ error: 'number is required' });
        createPayload = {
          name: 'AutoMod: Mention Spam',
          creatorId: client.user.id,
          enabled: true,
          eventType: AutoModerationRuleEventType.MessageSend,
          triggerType: AutoModerationRuleTriggerType.MentionSpam,
          triggerMetadata: { mentionTotalLimit: Number(number) },
          actions: [{ type: AutoModerationActionType.BlockMessage }]
        };
      } else if (type === 'keyword') {
        if (!word || String(word).trim().length === 0) return res.status(400).json({ error: 'word is required' });
        createPayload = {
          name: `AutoMod: Block '${word}'`,
          creatorId: client.user.id,
          enabled: true,
          eventType: AutoModerationRuleEventType.MessageSend,
          triggerType: AutoModerationRuleTriggerType.Keyword,
          triggerMetadata: { keywordFilter: [String(word)] },
          actions: [{ type: AutoModerationActionType.BlockMessage }]
        };
      } else if (type === 'anti-link') {
        createPayload = {
          name: 'Anti-Link',
          creatorId: client.user.id,
          enabled: true,
          eventType: AutoModerationRuleEventType.MessageSend,
          triggerType: AutoModerationRuleTriggerType.Keyword,
          triggerMetadata: { regexPatterns: linkPatterns },
          actions: [{ type: AutoModerationActionType.BlockMessage }]
        };
      } else {
        return res.status(400).json({ error: 'Invalid type' });
      }
      const rule = await guild.autoModerationRules.create(createPayload);
      res.json({ success: true, id: rule.id });
    } catch (error) {
      console.error('Error enabling automod rule:', error);
      res.status(500).json({ error: 'Failed to enable automod rule' });
    }
  });

  app.post('/api/guilds/:guildId/automod/disable', isAuthenticated, async (req, res) => {
    try {
      const guild = client.guilds.cache.get(req.params.guildId);
      if (!guild) return res.status(404).json({ error: 'Guild not found' });
      const member = await guild.members.fetch(req.user.id).catch(() => null);
      if (!member || !member.permissions.has(PermissionsBitField.Flags.ManageGuild)) {
        return res.status(403).json({ error: 'Missing permissions' });
      }
      const { type } = req.body;
      await guild.autoModerationRules.fetch();
      const rules = Array.from(guild.autoModerationRules.cache.values());
      const linkPatterns = [
        "http[s]?://",
        "www\\.",
        "\\.com",
        "\\.net",
        "\\.org",
        "discord\\.gg",
        "discord\\.com/invite",
        "t\\.me",
        "instagram\\.com",
        "youtu(be\\.com|\\.be)"
      ];
      let ruleToDisable = null;
      if (type === 'flagged-words') {
        ruleToDisable = rules.find(r => r.triggerType === AutoModerationRuleTriggerType.KeywordPreset && r.enabled);
      } else if (type === 'spam-messages') {
        ruleToDisable = rules.find(r => r.triggerType === AutoModerationRuleTriggerType.Spam && r.enabled);
      } else if (type === 'mention-spam') {
        ruleToDisable = rules.find(r => r.triggerType === AutoModerationRuleTriggerType.MentionSpam && r.enabled);
      } else if (type === 'keyword') {
        ruleToDisable = rules.find(
          r =>
            r.triggerType === AutoModerationRuleTriggerType.Keyword &&
            r.enabled &&
            r.triggerMetadata?.keywordFilter &&
            r.triggerMetadata.keywordFilter.length > 0
        );
      } else if (type === 'anti-link') {
        ruleToDisable = rules.find(
          r =>
            r.triggerType === AutoModerationRuleTriggerType.Keyword &&
            r.enabled &&
            Array.isArray(r.triggerMetadata?.regexPatterns) &&
            r.triggerMetadata.regexPatterns.some(p => linkPatterns.includes(p))
        );
      }
      if (!ruleToDisable) return res.status(404).json({ error: 'Rule not found' });
      await ruleToDisable.edit({ enabled: false }, `Disabled by ${req.user.id}`);
      res.json({ success: true });
    } catch (error) {
      console.error('Error disabling automod rule:', error);
      res.status(500).json({ error: 'Failed to disable automod rule' });
    }
  });

  // Guild management
  app.get('/guild/:id', isAuthenticated, async (req, res) => {
    console.log(`[Guild] Request received for guild ID: ${req.params.id}`);
    
    try {
      console.log('[Guild] Fetching guild from cache...');
      const guild = client.guilds.cache.get(req.params.id);
      
      if (!guild) {
        console.log(`[Guild] Guild ${req.params.id} not found in cache`);
        return res.status(404).render('error', { 
          title: 'Guild Not Found', 
          message: 'The requested server could not be found.' 
        });
      }

      console.log(`[Guild] Found guild: ${guild.name} (${guild.id})`);
      console.log(`[Guild] Fetching member data for user: ${req.user.id}...`);

      try {
        const member = await Promise.race([
          guild.members.fetch(req.user.id).catch(err => {
            console.error(`[Guild] Error fetching member:`, err);
            throw err;
          }),
          new Promise((_, reject) => 
            setTimeout(() => reject(new Error('Request timed out after 10 seconds')), 10000)
          )
        ]);

        console.log(`[Guild] Member data retrieved:`, { 
          id: member.id, 
          permissions: member.permissions.toArray() 
        });

        if (!member || !member.permissions.has('MANAGE_GUILD')) {
          console.log(`[Guild] User ${req.user.id} lacks MANAGE_GUILD permission`);
          return res.status(403).render('error', { 
            title: 'Access Denied', 
            message: 'You do not have permission to manage this server.' 
          });
        }

        console.log('[Guild] Fetching premium guild data...');
        const premiumGuild = await PremiumGuild.findOne({ id: req.params.id })
          .catch(err => {
            console.error('[Guild] Error fetching premium guild data:', err);
            return null;
          });
        
        console.log('[Guild] Rendering guild management page...');
        return res.render('guild', { 
          title: `${guild.name} - Management`, 
          guild, 
          premium: premiumGuild, 
          user: req.user,
          layout: 'layout' // Ensure layout is specified if you're using one
        });
        
      } catch (fetchError) {
        console.error('[Guild] Error in guild management route:', {
          error: fetchError.message,
          stack: fetchError.stack
        });
        return res.status(500).render('error', { 
          title: 'Server Error', 
          message: `Failed to load server information: ${fetchError.message}`,
          layout: 'layout'
        });
      }
    } catch (err) {
      console.error('Guild management error:', err);
      res.status(500).render('error', { 
        title: 'Internal Server Error', 
        message: 'An unexpected error occurred. Please try again later.',
        layout: 'layout'
      });
    }
  });

  // Admin panel
  app.get('/admin', isAuthenticated, isOwnerOrAdmin, async (req, res) => {
    try {
      const blacklistedUsers = await UserBlacklist.find();
      const blacklistedGuilds = await GuildBlacklist.find();
      const blacklistedIps = await IpBlacklist.find();
      const verifiedUsers = await VerifiedUser.find();
      const adminUsers = await AdminUser.find();
      const activeUsers = Array.from(req.app.locals?.activeUsers?.values() || []);
      res.render('admin', {
        title: 'Admin Panel',
        user: req.user,
        blacklistedUsers,
        blacklistedGuilds,
        blacklistedIps,
        verifiedUsers,
        adminUsers,
        activeUsers,
        stats: {
          guilds: client.guilds.cache.size,
          users: client.guilds.cache.reduce((a, b) => a + b.memberCount, 0),
          commands: client.commands.size,
          uptime: client.uptime,
        },
        guilds: Array.from(client.guilds.cache.values()).map(g => ({ id: g.id, name: g.name })),
        layout: 'layout'
      });
    } catch (err) {
      console.error(err);
      res.status(500).send('Internal Server Error');
    }
  });

  // Blacklist routes
  app.post('/admin/blacklist/user', isAuthenticated, isOwnerOrAdmin, async (req, res) => {
    const { userId, reason = 'No reason provided' } = req.body;
    await UserBlacklist.findOneAndUpdate({ userId }, { userId, reason }, { upsert: true, new: true });
    res.redirect('/admin');
  });

  app.post('/admin/unblacklist/user', isAuthenticated, isOwnerOrAdmin, async (req, res) => {
    const { userId } = req.body;
    await UserBlacklist.deleteOne({ userId });
    res.redirect('/admin');
  });

  app.post('/admin/blacklist/ip', isAuthenticated, isOwnerOrAdmin, async (req, res) => {
    const { ip, reason = 'No reason provided' } = req.body;
    if (!ip) return res.status(400).send('IP is required');
    await IpBlacklist.findOneAndUpdate(
      { ip },
      { ip, reason, addedBy: req.user.id },
      { upsert: true, new: true }
    );
    res.redirect('/admin');
  });

  app.post('/admin/unblacklist/ip', isAuthenticated, isOwnerOrAdmin, async (req, res) => {
    const { ip } = req.body;
    if (!ip) return res.status(400).send('IP is required');
    await IpBlacklist.deleteOne({ ip });
    res.redirect('/admin');
  });

  // Verified users routes
  app.post('/admin/verify/user', isAuthenticated, isOwnerOrAdmin, async (req, res) => {
    const { userId } = req.body;
    if (!userId) return res.status(400).send('User ID is required');
    await VerifiedUser.findOneAndUpdate(
      { userId },
      { userId, verified: true, grantedBy: req.user.id, grantedAt: new Date() },
      { upsert: true, new: true }
    );
    res.redirect('/admin');
  });

  app.post('/admin/unverify/user', isAuthenticated, isOwnerOrAdmin, async (req, res) => {
    const { userId } = req.body;
    if (!userId) return res.status(400).send('User ID is required');
    await VerifiedUser.deleteOne({ userId });
    res.redirect('/admin');
  });

  // Presence endpoint for navbar
  app.get('/api/users/me/presence', isAuthenticated, async (req, res) => {
    try {
      const sessionUser = req.user;
      if (!sessionUser?.id) return res.status(401).json({ status: 'offline' });
      const mutualGuilds = Array.isArray(sessionUser.guilds) ? sessionUser.guilds : [];
      let status = 'offline';
      for (const g of mutualGuilds) {
        const guild = client.guilds.cache.get(g.id);
        if (!guild) continue;
        const member = await guild.members.fetch(sessionUser.id).catch(() => null);
        if (member?.presence?.status) {
          status = member.presence.status;
          break;
        }
      }
      res.json({ status });
    } catch (err) {
      res.json({ status: 'offline' });
    }
  });

  // Admin utility endpoints
  app.post('/admin/restart', isAuthenticated, isOwnerOrAdmin, async (req, res) => {
    res.json({ success: true, message: 'Restarting bot process...' });
    setTimeout(() => process.exit(0), 500);
  });

  app.post('/admin/maintenance', isAuthenticated, isOwnerOrAdmin, (req, res) => {
    const { enabled } = req.body;
    maintenanceMode = !!enabled;
    res.json({ success: true, enabled: maintenanceMode });
  });

  app.get('/api/admin/maintenance', isAuthenticated, isOwnerOrAdmin, (req, res) => {
    res.json({ enabled: maintenanceMode });
  });

  app.post('/admin/cache/clear', isAuthenticated, isOwnerOrAdmin, async (req, res) => {
    try {
      client.users.cache.clear();
      client.channels?.cache?.clear?.();
      client.guilds.cache.forEach((g) => {
        g.members?.cache?.clear?.();
        g.invites?.cache?.clear?.();
      });
      res.json({ success: true, message: 'Caches cleared.' });
    } catch (err) {
      console.error('Cache clear error:', err);
      res.status(500).json({ error: 'Failed to clear cache.' });
    }
  });

  app.post('/admin/commands/reload', isAuthenticated, isOwnerOrAdmin, async (req, res) => {
    try {
      const cmds = await client.application?.commands?.fetch();
      res.json({ success: true, message: `Slash commands refreshed (${cmds?.size || 0} loaded).` });
    } catch (err) {
      console.error('Slash command reload error:', err);
      res.status(500).json({ error: 'Failed to reload slash commands.' });
    }
  });

  app.post('/admin/blacklist/guild/:guildId', isAuthenticated, isOwnerOrAdmin, async (req, res) => {
    const guildId = req.params.guildId;
    const reason = req.body.reason || 'No reason provided';
    await GuildBlacklist.findOneAndUpdate({ guildId }, { guildId, reason }, { upsert: true, new: true });
    res.redirect('/admin');
  });

  app.post('/admin/unblacklist/guild/:guildId', isAuthenticated, isOwnerOrAdmin, async (req, res) => {
    await GuildBlacklist.deleteOne({ guildId: req.params.guildId });
    res.redirect('/admin');
  });

  // API routes
  app.get('/api/stats', (req, res) => {
    res.json({
      guilds: client.guilds.cache.size,
      users: client.guilds.cache.reduce((a, b) => a + b.memberCount, 0),
      commands: client.commands.size,
      uptime: client.uptime,
    });
  });

  app.get('/api/user/:id/premium', async (req, res) => {
    const premium = await Premium.findOne({ id: req.params.id });
    res.json({ premium: !!premium, data: premium });
  });

  app.get('/api/guild/:id/premium', async (req, res) => {
    const premium = await PremiumGuild.findOne({ id: req.params.id });
    res.json({ premium: !!premium, data: premium });
  });

  // Welcome message endpoints
  app.get('/api/guilds/:guildId/welcome', isAuthenticated, async (req, res) => {
    try {
      const { guildId } = req.params;
      
      // Check if user has permission to view this guild's settings
      const guild = client.guilds.cache.get(guildId);
      if (!guild) {
        return res.status(404).json({ error: 'Guild not found' });
      }

      const member = await guild.members.fetch(req.user.id).catch(() => null);
      if (!member || !member.permissions.has(PermissionsBitField.Flags.ManageGuild)) {
        return res.status(403).json({ error: 'Missing permissions' });
      }

      // Get welcome settings
      let welcomeSettings = await WelcomeMessage.findOne({ guildId });
      
      // Default settings if not found
      if (!welcomeSettings) {
        welcomeSettings = {
          welcome: {
            enabled: false,
            channel: '',
            message: 'Welcome {user} to {server}! 🎉',
            dmEnabled: false,
            dmMessage: 'Thanks for joining {server}! Enjoy your stay!',
          },
          goodbye: {
            enabled: false,
            channel: '',
            message: '{user} has left {server}. Goodbye! 👋',
          },
        };
      } else {
        // Format the response to match the expected structure
        welcomeSettings = {
          welcome: {
            enabled: !!welcomeSettings.channelId,
            channel: welcomeSettings.channelId || '',
            message: welcomeSettings.message || 'Welcome {user} to {server}! 🎉',
            dmEnabled: false, // Not supported in the original schema
            dmMessage: 'Thanks for joining {server}! Enjoy your stay!',
          },
          goodbye: {
            enabled: false, // Not supported in the original schema
            channel: '',
            message: '{user} has left {server}. Goodbye! 👋',
          },
        };
      }

      res.json(welcomeSettings);
    } catch (error) {
      console.error('Error fetching welcome settings:', error);
      res.status(500).json({ error: 'Internal server error' });
    }
  });

  // Save welcome settings
  app.post('/api/guilds/:guildId/welcome', isAuthenticated, async (req, res) => {
    try {
      const { guildId } = req.params;
      const { welcome, goodbye } = req.body;
      
      // Check if user has permission to modify this guild's settings
      const guild = client.guilds.cache.get(guildId);
      if (!guild) {
        return res.status(404).json({ error: 'Guild not found' });
      }

      const member = await guild.members.fetch(req.user.id).catch(() => null);
      if (!member || !member.permissions.has(PermissionsBitField.Flags.ManageGuild)) {
        return res.status(403).json({ error: 'Missing permissions' });
      }

      // Save welcome settings
      await WelcomeMessage.findOneAndUpdate(
        { guildId },
        {
          guildId,
          channelId: welcome?.channel || '',
          message: welcome?.message || 'Welcome {user} to {server}! 🎉',
          isEmbed: false,
          isImage: false,
        },
        { upsert: true, new: true }
      );

      res.json({ success: true });
    } catch (error) {
      console.error('Error saving welcome settings:', error);
      res.status(500).json({ error: 'Internal server error' });
    }
  });

  // Note: The /api/guilds/:guildId/channels endpoint is defined earlier in the file

  // API: Get guild roles
  app.get('/api/guilds/:guildId/roles', isAuthenticated, async (req, res) => {
    try {
      const guild = client.guilds.cache.get(req.params.guildId);
      if (!guild) return res.status(404).json({ error: 'Guild not found' });
      const member = await guild.members.fetch(req.user.id).catch(() => null);
      if (!member || !member.permissions.has(PermissionsBitField.Flags.ManageGuild)) {
        return res.status(403).json({ error: 'Missing permissions' });
      }
      const roles = Array.from(guild.roles.cache.values())
        .sort((a, b) => b.position - a.position)
        .map(r => ({ id: r.id, name: r.name, position: r.position }));
      return res.json(roles);
    } catch (error) {
      console.error('Error fetching roles:', error);
      res.status(500).json({ error: 'Failed to fetch roles' });
    }
  });

  // API: Get guild categories
  app.get('/api/guilds/:guildId/categories', isAuthenticated, async (req, res) => {
    try {
      const guild = client.guilds.cache.get(req.params.guildId);
      if (!guild) return res.status(404).json({ error: 'Guild not found' });
      const member = await guild.members.fetch(req.user.id).catch(() => null);
      if (!member || !member.permissions.has(PermissionsBitField.Flags.ManageGuild)) {
        return res.status(403).json({ error: 'Missing permissions' });
      }
      const channels = await guild.channels.fetch();
      const categories = Array.from(channels.values())
        .filter(ch => ch.type === 4)
        .sort((a, b) => a.rawPosition - b.rawPosition)
        .map(c => ({ id: c.id, name: c.name, position: c.rawPosition }));
      return res.json(categories);
    } catch (error) {
      console.error('Error fetching categories:', error);
      res.status(500).json({ error: 'Failed to fetch categories' });
    }
  });

  // API: Ticket setup - get
  app.get('/api/guilds/:guildId/tickets/setup', isAuthenticated, async (req, res) => {
    try {
      const guild = client.guilds.cache.get(req.params.guildId);
      if (!guild) return res.status(404).json({ error: 'Guild not found' });
      const member = await guild.members.fetch(req.user.id).catch(() => null);
      if (!member || !member.permissions.has(PermissionsBitField.Flags.ManageGuild)) {
        return res.status(403).json({ error: 'Missing permissions' });
      }
      const setup = await TicketSetup.findOne({ GuildID: guild.id });
      const defaults = {
        GuildID: guild.id,
        Channel: '',
        Category: '',
        Transcripts: '',
        Handlers: '',
        Everyone: '',
        Description: '',
        Categories: []
      };
      res.json(setup || defaults);
    } catch (error) {
      console.error('Error fetching ticket setup:', error);
      res.status(500).json({ error: 'Failed to fetch ticket setup' });
    }
  });

  // API: Ticket setup - save
  app.post('/api/guilds/:guildId/tickets/setup', isAuthenticated, async (req, res) => {
    try {
      const guild = client.guilds.cache.get(req.params.guildId);
      if (!guild) return res.status(404).json({ error: 'Guild not found' });
      const member = await guild.members.fetch(req.user.id).catch(() => null);
      if (!member || !member.permissions.has(PermissionsBitField.Flags.ManageGuild)) {
        return res.status(403).json({ error: 'Missing permissions' });
      }
      const payload = req.body || {};
      const doc = {
        GuildID: guild.id,
        Channel: payload.Channel || '',
        Category: payload.Category || '',
        Transcripts: payload.Transcripts || '',
        Handlers: payload.Handlers || '',
        Everyone: payload.Everyone || '',
        Description: payload.Description || '',
        Categories: Array.isArray(payload.Categories) ? payload.Categories.map(c => ({
          emoji: String(c.emoji || ''),
          name: String(c.name || ''),
          value: String(c.value || ''),
          description: String(c.description || ''),
          ticketCategory: String(c.ticketCategory || '')
        })) : []
      };
      const saved = await TicketSetup.findOneAndUpdate(
        { GuildID: guild.id },
        doc,
        { upsert: true, new: true }
      );
      res.json({ success: true, setup: saved });
    } catch (error) {
      console.error('Error saving ticket setup:', error);
      res.status(500).json({ error: 'Failed to save ticket setup' });
    }
  });

  // API: Send ticket panel to configured channel
  app.post('/api/guilds/:guildId/tickets/panel/send', isAuthenticated, async (req, res) => {
    try {
      const guild = client.guilds.cache.get(req.params.guildId);
      if (!guild) return res.status(404).json({ error: 'Guild not found' });
      const member = await guild.members.fetch(req.user.id).catch(() => null);
      if (!member || !member.permissions.has(PermissionsBitField.Flags.ManageGuild)) {
        return res.status(403).json({ error: 'Missing permissions' });
      }
      const setup = await TicketSetup.findOne({ GuildID: guild.id });
      if (!setup) return res.status(400).json({ error: 'Ticket system is not configured' });
      if (!setup.Channel) return res.status(400).json({ error: 'Ticket panel channel is not set' });
      if (!setup.Categories || setup.Categories.length === 0) {
        return res.status(400).json({ error: 'At least one ticket category is required' });
      }
      const channel = guild.channels.cache.get(setup.Channel) || await guild.channels.fetch(setup.Channel).catch(() => null);
      if (!channel) return res.status(404).json({ error: 'Configured ticket channel not found' });
      const botMember = guild.members.me || await guild.members.fetchMe();
      const perms = channel.permissionsFor(botMember);
      if (!perms?.has(PermissionsBitField.Flags.ViewChannel) || !perms?.has(PermissionsBitField.Flags.SendMessages)) {
        return res.status(403).json({ error: 'Bot lacks permission to send messages in the configured channel' });
      }
      const embed = new EmbedBuilder()
        .setTitle(ticketConfig.ticketMessageTitle)
        .setDescription(ticketConfig.ticketMessageDescription)
        .setColor(client.config?.embedColor ?? 0x5865F2)
        .setAuthor({ name: guild.name, iconURL: guild.iconURL({ dynamic: true }) })
        .setTimestamp();
      const options = setup.Categories.map(c =>
        new StringSelectMenuOptionBuilder()
          .setLabel(c.name)
          .setDescription(c.description || `Create a ${c.name} ticket`)
          .setValue(c.value || c.name.toLowerCase().replace(/\s+/g, '-'))
          .setEmoji(c.emoji || undefined)
      );
      const select = new StringSelectMenuBuilder()
        .setCustomId('ticket-dropdown')
        .setPlaceholder('Select a ticket type')
        .addOptions(options);
      const row = new ActionRowBuilder().addComponents(select);
      const sent = await channel.send({ embeds: [embed], components: [row] });
      res.json({ success: true, channelId: channel.id, messageId: sent.id });
    } catch (error) {
      console.error('Error sending ticket panel:', error);
      res.status(500).json({ error: 'Failed to send ticket panel' });
    }
  });

  // Logging routes
  app.get('/api/guilds/:guildId/logs', isAuthenticated, async (req, res) => {
    try {
      const guild = client.guilds.cache.get(req.params.guildId);
      if (!guild) {
        return res.status(404).json({ error: 'Guild not found' });
      }

      // Check if user has permission to view logs
      const member = await guild.members.fetch(req.user.id).catch(() => null);
      if (!member || !member.permissions.has('ADMINISTRATOR')) {
        return res.status(403).json({ error: 'Missing permissions' });
      }

      // Get or create log settings
      let logSettings = await logSchema.findOne({ Guild: guild.id });
      
      if (!logSettings) {
        logSettings = new logSchema({
          Guild: guild.id,
          LogChannels: {
            all: '',
            message: '',
            channel: '',
            guild: '',
            role: '',
            voice: '',
            member: ''
          }
        });
        await logSettings.save();
      }

      res.json({
        success: true,
        logs: logSettings.LogChannels
      });

    } catch (error) {
      console.error('Error fetching log settings:', error);
      res.status(500).json({ error: 'Failed to fetch log settings' });
    }
  });

  // Update log settings
  app.post('/api/guilds/:guildId/logs', isAuthenticated, async (req, res) => {
    try {
      const { logType, channelId } = req.body;
      const guild = client.guilds.cache.get(req.params.guildId);
      
      if (!guild) {
        return res.status(404).json({ error: 'Guild not found' });
      }

      // Check if user has permission to update logs
      const member = await guild.members.fetch(req.user.id).catch(() => null);
      if (!member || !member.permissions.has('ADMINISTRATOR')) {
        return res.status(403).json({ error: 'Missing permissions' });
      }

      // Validate log type
      const validLogTypes = ['all', 'message', 'channel', 'guild', 'role', 'voice', 'member'];
      if (!validLogTypes.includes(logType)) {
        return res.status(400).json({ error: 'Invalid log type' });
      }

      // Get current settings or create new ones
      let logSettings = await logSchema.findOne({ Guild: guild.id });
      if (!logSettings) {
        logSettings = new logSchema({
          Guild: guild.id,
          LogChannels: {
            all: '',
            message: '',
            channel: '',
            guild: '',
            role: '',
            voice: '',
            member: ''
          }
        });
      }

      // Update the specific log type
      logSettings.LogChannels[logType] = channelId || '';
      await logSettings.save();

      res.json({
        success: true,
        message: 'Log settings updated',
        logs: logSettings.LogChannels
      });

    } catch (error) {
      console.error('Error updating log settings:', error);
      res.status(500).json({ error: 'Failed to update log settings' });
    }
  });

  // Clear log settings
  app.delete('/api/guilds/:guildId/logs', isAuthenticated, async (req, res) => {
    try {
      const { logType } = req.body;
      const guild = client.guilds.cache.get(req.params.guildId);
      
      if (!guild) {
        return res.status(404).json({ error: 'Guild not found' });
      }

      // Check if user has permission to update logs
      const member = await guild.members.fetch(req.user.id).catch(() => null);
      if (!member || !member.permissions.has('ADMINISTRATOR')) {
        return res.status(403).json({ error: 'Missing permissions' });
      }

      // Get current settings or create new ones
      let logSettings = await logSchema.findOne({ Guild: guild.id });
      if (!logSettings) {
        logSettings = new logSchema({
          Guild: guild.id,
          LogChannels: {
            all: '',
            message: '',
            channel: '',
            guild: '',
            role: '',
            voice: '',
            member: ''
          }
        });
      }

      if (logType === 'all') {
        // Clear all log settings
        logSettings.LogChannels = {
          all: '',
          message: '',
          channel: '',
          guild: '',
          role: '',
          voice: '',
          member: ''
        };
      } else if (logType) {
        // Clear specific log type
        logSettings.LogChannels[logType] = '';
      } else {
        return res.status(400).json({ error: 'Log type is required' });
      }

      await logSettings.save();

      res.json({
        success: true,
        message: logType === 'all' ? 'All log settings cleared' : 'Log setting cleared',
        logs: logSettings.LogChannels
      });

    } catch (error) {
      console.error('Error clearing log settings:', error);
      res.status(500).json({ error: 'Failed to clear log settings' });
    }
  });

  // 404 handler
  app.use((req, res) => {
    res.status(404).render('404', { title: 'Page Not Found' });
  });
};
