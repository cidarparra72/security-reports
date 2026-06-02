// app.js - Sample Alipay Mini Program
// This file contains intentional security issues for testing

App({
  onLaunch(options) {
    // VULNERABILITY: Hardcoded API key
    const API_KEY = "sk_live_abc123xyz789";
    
    // VULNERABILITY: Hardcoded credentials
    const DB_HOST = "admin:password123@db.example.com";
    
    // VULNERABILITY: Insecure HTTP URL
    const API_BASE_URL = "http://api.example.com/v1";
    
    console.log('App launched', options);
  },
  
  // VULNERABILITY: Missing authentication check
  getUserData(userId) {
    my.request({
      url: 'https://api.example.com/users/' + userId,
      success: function(res) {
        console.log(res.data);
      }
    });
  },
  
  // VULNERABILITY: SQL Injection possible
  searchProducts(query) {
    const sql = "SELECT * FROM products WHERE name LIKE '%" + query + "%'";
    my.request({
      url: 'https://api.example.com/search',
      data: { q: sql },
      method: 'POST'
    });
  },
  
  // VULNERABILITY: XSS via innerHTML
  displayMessage(message) {
    const div = document.createElement('div');
    div.innerHTML = message; // XSS vulnerability
    document.body.appendChild(div);
  },
  
  // VULNERABILITY: JWT token in localStorage
  saveToken(token) {
    my.setStorageSync('auth_token', token);
  },
  
  getToken() {
    return my.getStorageSync('auth_token');
  }
});