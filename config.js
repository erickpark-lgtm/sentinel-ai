/**
 * SentinelAI Global Environment Configuration (config.js)
 * Dynamically switches API endpoints between local dev, Render/Railway cloud backends,
 * and production custom domains (https://api.sentinelvciso.com).
 */
window.SENTINEL_CONFIG = {
  // Render deployed cloud backend:
  CLOUD_API_URL: 'https://sentinel-ai-1-2rt1.onrender.com',

  getApiBaseUrl: function() {
    // 1. URL Query Parameter override for instant zero-redeploy testing: ?api_url=https://...
    const urlParams = new URLSearchParams(window.location.search);
    const paramOverride = urlParams.get('api_url');
    if (paramOverride) return paramOverride.replace(/\/$/, '');

    // 2. Window variable override
    if (window.SENTINEL_API_URL) return window.SENTINEL_API_URL.replace(/\/$/, '');

    // 3. Localhost development
    if (window.location.hostname === 'localhost' || window.location.hostname === '127.0.0.1') {
      return window.location.port === '8090' ? '' : 'http://localhost:8090';
    }

    // 4. Production default (api.sentinelvciso.com or Render/Railway)
    return this.CLOUD_API_URL.replace(/\/$/, '');
  }
};
