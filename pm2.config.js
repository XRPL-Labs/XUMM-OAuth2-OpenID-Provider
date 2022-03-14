module.exports = {
  apps: [{
    name: 'oauth2-server',
    script: 'index.js',
    watch: false,
    instances: 1,
    exec_mode: 'fork',
    ignore_watch: ["node_modules", "db", ".git"],
    env: {}
  }]
}
