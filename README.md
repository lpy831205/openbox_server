# 李端棻中学报名记录查询系统 - 服务端安全改进

本文档描述了服务端的安全改进措施及前端需要配合的变更。

## 安全改进摘要

1. **密码存储增强**
   - 使用Argon2id算法替代简单SHA-256哈希
   - 自动兼容旧密码格式，无需用户重置密码

2. **RSA密钥管理增强**
   - 私钥加密存储
   - 使用环境变量或服务器唯一标识作为密钥加密密码

3. **令牌持久化存储**
   - 令牌存储在文件系统而非内存
   - 服务器重启不会导致用户需要重新登录

4. **新增登出功能**
   - 添加`/api/auth/logout`接口
   - 支持用户主动登出，提高安全性

## 前端需要配合的变更

### 1. 登出功能

前端需要实现登出功能，调用新增的登出API：

```javascript
async function logout() {
  try {
    const response = await fetch('/api/auth/logout', {
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${token}`,
        'X-Encrypted-Key': encryptedKey,
        'X-Signature': signature,
        'X-Nonce': nonce,
        'X-Timestamp': timestamp,
        'X-Client-IP': clientIP
      }
    });
    
    if (response.ok) {
      // 清除本地存储的令牌和用户信息
      localStorage.removeItem('token');
      localStorage.removeItem('userInfo');
      // 跳转到登录页面
      window.location.href = '/login';
    }
  } catch (error) {
    console.error('登出失败:', error);
  }
}
```

### 2. 密码复杂度要求

前端应当实现密码复杂度检查，确保密码符合以下要求：
- 至少6个字符
- 至少包含一个小写字母
- 至少包含一个大写字母
- 至少包含一个数字

```javascript
function isPasswordStrong(password) {
  const regex = /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)[a-zA-Z\d]{6,}$/;
  return regex.test(password);
}
```

### 3. 令牌刷新机制

前端可以实现自动令牌刷新机制，在令牌即将过期时调用刷新接口：

```javascript
function setupTokenRefresh(expiryTime) {
  const expiryDate = new Date(expiryTime);
  const now = new Date();
  
  // 计算令牌过期前5分钟的时间点
  const refreshTime = new Date(expiryDate.getTime() - 5 * 60 * 1000);
  
  // 如果已经过了刷新时间点，立即刷新
  if (now >= refreshTime) {
    refreshToken();
    return;
  }
  
  // 否则，设置定时器在刷新时间点刷新令牌
  const timeUntilRefresh = refreshTime.getTime() - now.getTime();
  setTimeout(refreshToken, timeUntilRefresh);
}

async function refreshToken() {
  try {
    // 调用刷新令牌API
    const response = await fetch('/api/auth/refresh-token', {
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${token}`,
        'X-Encrypted-Key': encryptedKey,
        'X-Signature': signature,
        'X-Nonce': nonce,
        'X-Timestamp': timestamp,
        'X-Client-IP': clientIP
      }
    });
    
    if (response.ok) {
      const data = await response.json();
      // 解密响应数据
      const decryptedData = decryptResponse(data);
      
      // 更新本地存储的令牌和过期时间
      localStorage.setItem('token', decryptedData.token);
      
      // 设置下一次令牌刷新
      setupTokenRefresh(decryptedData.expiry);
    }
  } catch (error) {
    console.error('令牌刷新失败:', error);
    // 如果刷新失败，可能需要重定向到登录页面
    window.location.href = '/login';
  }
}
```

## 环境变量配置

服务器需要配置以下环境变量：

```
RSA_KEY_PASSWORD=<强密码用于加密RSA私钥>
```

如果未设置此环境变量，系统将使用服务器特定信息生成密码。

## 安全最佳实践

1. **定期更新密码**
   - 建议用户定期更改密码
   - 管理员可以强制重置密码

2. **定期轮换RSA密钥**
   - 建议每3-6个月轮换一次RSA密钥对
   - 轮换时需要重新生成所有邀请码

3. **监控可疑活动**
   - 定期检查服务器日志
   - 关注登录失败和安全违规记录

4. **数据备份**
   - 定期备份用户数据和查询记录
   - 确保备份文件加密存储
