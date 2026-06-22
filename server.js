const express = require('express');
const cors = require('cors');
const fs = require('fs');
const path = require('path');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = 'bear-app-secret-key-2024';

// 数据文件路径
const DB_FILE = path.join(__dirname, 'database.json');

console.log('='.repeat(60));
console.log('📦 数据库文件路径:', DB_FILE);
console.log('='.repeat(60));

// ==================== 数据库操作函数 ====================

// 初始化数据库
const initDatabase = () => {
  console.log('\n[INIT] 开始初始化数据库...');
  
  if (!fs.existsSync(DB_FILE)) {
    console.log('[INIT] 创建新的数据库文件...');
    
    // 预先生成admin密码哈希
    const adminHash = bcrypt.hashSync('123456', 10);
    console.log('[INIT] admin密码哈希:', adminHash);
    
    // 验证哈希是否正确
    const testVerify = bcrypt.compareSync('123456', adminHash);
    console.log('[INIT] admin密码验证测试:', testVerify ? '✅ 通过' : '❌ 失败');
    
    const defaultData = {
      users: [
        {
          id: 1,
          username: 'admin',
          email: 'admin@bear.com',
          password: adminHash,
          createdAt: new Date().toISOString()
        }
      ]
    };
    fs.writeFileSync(DB_FILE, JSON.stringify(defaultData, null, 2));
    console.log('[INIT] ✅ 默认测试账号已创建: admin / 123456');
  } else {
    console.log('[INIT] ✅ 数据库文件已存在');
  }
  
  const data = JSON.parse(fs.readFileSync(DB_FILE, 'utf8'));
  console.log(`[INIT] 📊 当前用户总数: ${data.users.length}`);
  data.users.forEach(u => {
    console.log(`[INIT]   - 用户: ${u.username}, ID: ${u.id}`);
  });
  return data;
};

// 读取数据库
const readDB = () => {
  console.log('[DB] 读取数据库文件...');
  const data = JSON.parse(fs.readFileSync(DB_FILE, 'utf8'));
  console.log(`[DB] 读取完成，共 ${data.users.length} 个用户`);
  return data;
};

// 写入数据库
const writeDB = (data) => {
  console.log('[DB] 写入数据库文件...');
  fs.writeFileSync(DB_FILE, JSON.stringify(data, null, 2));
  console.log('[DB] ✅ 写入完成');
};

// ==================== 中间件 ====================
app.use(cors());
app.use(express.json());

// 请求日志中间件
app.use((req, res, next) => {
  console.log(`\n[REQUEST] ${new Date().toLocaleString()} - ${req.method} ${req.url}`);
  next();
});

// 初始化数据库
let db = initDatabase();

// ==================== Token验证中间件 ====================
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) {
    console.log('[AUTH] ❌ 未授权访问: 缺少Token');
    return res.status(401).json({ 
      success: false, 
      message: '未授权访问，请先登录' 
    });
  }

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) {
      console.log('[AUTH] ❌ Token无效:', err.message);
      return res.status(403).json({ 
        success: false, 
        message: 'Token无效或已过期，请重新登录' 
      });
    }
    req.user = user;
    next();
  });
};

// ==================== 重置密码接口 ====================
app.post('/api/reset-password', (req, res) => {
  console.log('\n[RESET-PASSWORD] ========================================');
  console.log('[RESET-PASSWORD] 收到重置密码请求:', JSON.stringify(req.body, null, 2));
  
  try {
    const { username, email, newPassword } = req.body;
    
    // 1. 读取最新数据库
    console.log('[RESET-PASSWORD] 步骤1: 读取最新数据库');
    db = readDB();

    // 2. 验证输入
    console.log('[RESET-PASSWORD] 步骤2: 验证输入');
    if (!username || !email || !newPassword) {
      console.log('[RESET-PASSWORD] ❌ 失败: 信息不完整');
      return res.status(400).json({ 
        success: false, 
        message: '请填写完整信息' 
      });
    }
    
    if (newPassword.length < 6) {
      console.log('[RESET-PASSWORD] ❌ 失败: 密码长度不足6位');
      return res.status(400).json({ 
        success: false, 
        message: '新密码至少需要6位' 
      });
    }
    
    console.log('[RESET-PASSWORD]   用户名:', username);
    console.log('[RESET-PASSWORD]   邮箱:', email);

    // 3. 查找用户
    console.log('[RESET-PASSWORD] 步骤3: 查找用户');
    const userIndex = db.users.findIndex(u => u.username === username && u.email === email);
    if (userIndex === -1) {
      console.log(`[RESET-PASSWORD] ❌ 失败: 用户名或邮箱不匹配`);
      return res.status(400).json({ 
        success: false, 
        message: '用户名与注册邮箱不匹配' 
      });
    }

    // 4. 加密新密码
    console.log('[RESET-PASSWORD] 步骤4: 加密新密码');
    const hashedPassword = bcrypt.hashSync(newPassword, 10);
    console.log('[RESET-PASSWORD]   新密码哈希:', hashedPassword);

    // 5. 更新用户密码
    console.log('[RESET-PASSWORD] 步骤5: 更新用户密码');
    db.users[userIndex].password = hashedPassword;
    writeDB(db);

    console.log('[RESET-PASSWORD] ✅ 成功: 密码已重置');
    res.json({ 
      success: true, 
      message: '密码重置成功！请使用新密码登录' 
    });

  } catch (error) {
    console.log('[RESET-PASSWORD] ❌ 服务器错误:', error);
    res.status(500).json({ 
      success: false, 
      message: '服务器错误，请稍后重试' 
    });
  }
});

// ==================== 用户注册接口 ====================
app.post('/api/register', (req, res) => {
  console.log('\n[REGISTER] ========================================');
  console.log('[REGISTER] 收到注册请求:', JSON.stringify(req.body, null, 2));
  
  try {
    const { username, email, password } = req.body;
    
    // 1. 读取最新数据库
    console.log('[REGISTER] 步骤1: 读取最新数据库');
    db = readDB();

    // 2. 验证输入
    console.log('[REGISTER] 步骤2: 验证输入');
    if (!username || !email || !password) {
      console.log('[REGISTER] ❌ 失败: 信息不完整');
      return res.status(400).json({ 
        success: false, 
        message: '请填写完整信息（用户名、邮箱、密码）' 
      });
    }
    console.log('[REGISTER]   用户名:', username);
    console.log('[REGISTER]   邮箱:', email);
    console.log('[REGISTER]   密码:', password);

    // 3. 检查用户名是否已存在
    console.log('[REGISTER] 步骤3: 检查用户名是否存在');
    const existingUser = db.users.find(u => u.username === username);
    if (existingUser) {
      console.log(`[REGISTER] ❌ 失败: 用户名 ${username} 已存在`);
      return res.status(400).json({ 
        success: false, 
        message: '用户名已存在，请换一个' 
      });
    }
    console.log('[REGISTER]   用户名可用 ✓');

    // 4. 检查邮箱是否已存在
    console.log('[REGISTER] 步骤4: 检查邮箱是否存在');
    const existingEmail = db.users.find(u => u.email === email);
    if (existingEmail) {
      console.log(`[REGISTER] ❌ 失败: 邮箱 ${email} 已被注册`);
      return res.status(400).json({ 
        success: false, 
        message: '该邮箱已被注册' 
      });
    }
    console.log('[REGISTER]   邮箱可用 ✓');

    // 5. 加密密码
    console.log('[REGISTER] 步骤5: 加密密码');
    console.log('[REGISTER]   原始密码:', password);
    const hashedPassword = bcrypt.hashSync(password, 10);
    console.log('[REGISTER]   加密后哈希:', hashedPassword);
    
    // 立即验证加密是否正确
    const verifyTest = bcrypt.compareSync(password, hashedPassword);
    console.log('[REGISTER]   加密验证测试:', verifyTest ? '✅ 通过' : '❌ 失败');

    // 6. 创建新用户
    console.log('[REGISTER] 步骤6: 创建新用户');
    const newUser = {
      id: db.users.length + 1,
      username,
      email,
      password: hashedPassword,
      createdAt: new Date().toISOString()
    };

    // 7. 保存到数据库
    console.log('[REGISTER] 步骤7: 保存到数据库');
    db.users.push(newUser);
    writeDB(db);
    
    // 8. 验证是否保存成功
    console.log('[REGISTER] 步骤8: 验证保存结果');
    const verifyDB = readDB();
    const savedUser = verifyDB.users.find(u => u.username === username);
    if (savedUser) {
      console.log('[REGISTER] ✅ 用户已成功保存到数据库');
      console.log('[REGISTER]   保存的密码哈希:', savedUser.password);
      
      // 再次验证登录
      const loginTest = bcrypt.compareSync(password, savedUser.password);
      console.log('[REGISTER]   登录模拟测试:', loginTest ? '✅ 可以正常登录' : '❌ 登录会失败');
    } else {
      console.log('[REGISTER] ⚠️ 警告: 用户未在数据库中找到！');
    }

    console.log(`[REGISTER] ✅ 注册成功! 用户ID: ${newUser.id}, 用户名: ${username}`);

    res.json({
      success: true,
      message: '注册成功！请使用新账号登录',
      user: {
        id: newUser.id,
        username,
        email
      }
    });
  } catch (error) {
    console.error('[REGISTER] ❌ 服务器错误:', error);
    res.status(500).json({ 
      success: false, 
      message: '服务器错误: ' + error.message 
    });
  }
});

// ==================== 用户登录接口 ====================
app.post('/api/login', (req, res) => {
  console.log('\n[LOGIN] ========================================');
  console.log('[LOGIN] 收到登录请求:', JSON.stringify(req.body, null, 2));
  
  try {
    const { username, password } = req.body;
    
    // 1. 读取最新数据库
    console.log('[LOGIN] 步骤1: 读取最新数据库');
    db = readDB();

    // 2. 验证输入
    console.log('[LOGIN] 步骤2: 验证输入');
    if (!username || !password) {
      console.log('[LOGIN] ❌ 失败: 信息不完整');
      return res.status(400).json({ 
        success: false, 
        message: '请输入用户名和密码' 
      });
    }
    console.log('[LOGIN]   用户名:', username);
    console.log('[LOGIN]   输入密码:', password);

    // 3. 查找用户
    console.log('[LOGIN] 步骤3: 查找用户');
    const user = db.users.find(u => u.username === username);
    if (!user) {
      console.log(`[LOGIN] ❌ 失败: 用户 ${username} 不存在`);
      console.log('[LOGIN]   数据库中现有用户:', db.users.map(u => u.username).join(', '));
      return res.status(400).json({ 
        success: false, 
        message: '用户名或密码错误' 
      });
    }
    console.log('[LOGIN]   找到用户 ✓');
    console.log('[LOGIN]   存储的密码哈希:', user.password);

    // 4. 验证密码 - 关键！
    console.log('[LOGIN] 步骤4: 验证密码');
    console.log('[LOGIN]   输入密码:', password);
    console.log('[LOGIN]   存储哈希:', user.password);
    
    const validPassword = bcrypt.compareSync(password, user.password);
    console.log('[LOGIN]   密码比对结果:', validPassword ? '✅ 正确' : '❌ 错误');
    
    if (!validPassword) {
      console.log(`[LOGIN] ❌ 失败: 用户 ${username} 密码错误`);
      return res.status(400).json({ 
        success: false, 
        message: '用户名或密码错误' 
      });
    }

    // 5. 生成token
    console.log('[LOGIN] 步骤5: 生成Token');
    const token = jwt.sign(
      { id: user.id, username: user.username },
      JWT_SECRET,
      { expiresIn: '24h' }
    );

    console.log(`[LOGIN] ✅ 登录成功! 用户: ${username}`);

    res.json({
      success: true,
      message: '登录成功！欢迎来到熊出没乐园！',
      token,
      user: {
        id: user.id,
        username: user.username,
        email: user.email,
        createdAt: user.createdAt
      }
    });
  } catch (error) {
    console.error('[LOGIN] ❌ 服务器错误:', error);
    res.status(500).json({ 
      success: false, 
      message: '服务器错误: ' + error.message 
    });
  }
});

// ==================== 获取用户信息接口 ====================
app.get('/api/user/profile', authenticateToken, (req, res) => {
  console.log('\n[PROFILE] ========================================');
  console.log('[PROFILE] 获取用户信息 - 用户ID:', req.user.id);
  
  try {
    db = readDB();
    const user = db.users.find(u => u.id === req.user.id);
    
    if (!user) {
      console.log('[PROFILE] ❌ 用户不存在');
      return res.status(404).json({
        success: false,
        message: '用户不存在'
      });
    }
    
    console.log('[PROFILE] ✅ 获取用户信息成功:', user.username);
    
    res.json({
      success: true,
      data: {
        id: user.id,
        username: user.username,
        email: user.email,
        createdAt: user.createdAt
      }
    });
  } catch (error) {
    console.error('[PROFILE] ❌ 服务器错误:', error);
    res.status(500).json({
      success: false,
      message: '服务器错误: ' + error.message
    });
  }
});

// ==================== 修改密码接口 ====================
app.post('/api/user/change-password', authenticateToken, (req, res) => {
  console.log('\n[CHANGE-PASSWORD] ========================================');
  console.log('[CHANGE-PASSWORD] 修改密码请求 - 用户ID:', req.user.id);
  
  try {
    const { oldPassword, newPassword } = req.body;
    
    // 验证输入
    if (!oldPassword || !newPassword) {
      console.log('[CHANGE-PASSWORD] ❌ 密码不能为空');
      return res.status(400).json({
        success: false,
        message: '请输入旧密码和新密码'
      });
    }
    
    if (newPassword.length < 6) {
      console.log('[CHANGE-PASSWORD] ❌ 新密码太短');
      return res.status(400).json({
        success: false,
        message: '新密码长度不能少于6位'
      });
    }
    
    db = readDB();
    const userIndex = db.users.findIndex(u => u.id === req.user.id);
    
    if (userIndex === -1) {
      console.log('[CHANGE-PASSWORD] ❌ 用户不存在');
      return res.status(404).json({
        success: false,
        message: '用户不存在'
      });
    }
    
    const user = db.users[userIndex];
    
    // 验证旧密码
    console.log('[CHANGE-PASSWORD] 验证旧密码...');
    const validOldPassword = bcrypt.compareSync(oldPassword, user.password);
    
    // 校验新密码不能与旧密码相同
    if (oldPassword === newPassword) {
      console.log('[CHANGE-PASSWORD] ❌ 新密码与旧密码相同');
      return res.status(400).json({
        success: false,
        message: '新密码不能与旧密码相同，请更换新密码'
      });
    }
    if (!validOldPassword) {
      console.log('[CHANGE-PASSWORD] ❌ 旧密码错误');
      return res.status(400).json({
        success: false,
        message: '旧密码错误'
      });
    }
    
    // 加密新密码
    console.log('[CHANGE-PASSWORD] 加密新密码...');
    const newHashedPassword = bcrypt.hashSync(newPassword, 10);
    
    // 更新密码
    db.users[userIndex].password = newHashedPassword;
    writeDB(db);
    
    console.log('[CHANGE-PASSWORD] ✅ 密码修改成功!');
    
    res.json({
      success: true,
      message: '密码修改成功！请使用新密码重新登录'
    });
  } catch (error) {
    console.error('[CHANGE-PASSWORD] ❌ 服务器错误:', error);
    res.status(500).json({
      success: false,
      message: '服务器错误: ' + error.message
    });
  }
});

// ==================== 视频相关接口 ====================
app.get('/api/videos', authenticateToken, (req, res) => {
  console.log('[API] 📺 获取视频列表 - 用户:', req.user.username);
  const videos = [
    {
      id: 1,
      title: '熊出没之过年',
      episode: '特别篇',
      description: '光头强要回家过年，熊大熊二帮助他顺利回家的温馨故事。',
      videoUrl: 'https://www.w3schools.com/html/mov_bbb.mp4'
    },
    {
      id: 2,
      title: '熊出没之夺宝熊兵',
      episode: '大电影',
      description: '熊大熊二和光头强意外遇到小女孩嘟嘟，展开了一场冒险。',
      videoUrl: 'https://www.w3schools.com/html/mov_bbb.mp4'
    },
    {
      id: 3,
      title: '熊出没之雪岭熊风',
      episode: '大电影',
      description: '熊二遇到了传说中的山神，展开了一段奇幻冒险。',
      videoUrl: 'https://www.w3schools.com/html/mov_bbb.mp4'
    },
    {
      id: 4,
      title: '熊出没之环球大冒险',
      episode: '第1集',
      description: '熊大熊二走出森林，来到城市开始全新的冒险。',
      videoUrl: 'https://www.w3schools.com/html/mov_bbb.mp4'
    },
    {
      id: 5,
      title: '熊出没之丛林总动员',
      episode: '第1集',
      description: '回到丛林的熊大熊二，继续保护森林的故事。',
      videoUrl: 'https://www.w3schools.com/html/mov_bbb.mp4'
    },
    {
      id: 6,
      title: '熊出没之秋日团团转',
      episode: '第1集',
      description: '秋天来临，森林里发生了许多有趣的故事。',
      videoUrl: 'https://www.w3schools.com/html/mov_bbb.mp4'
    }
  ];

  res.json({
    success: true,
    data: videos
  });
});

// ==================== 内容相关接口 ====================
app.get('/api/series', authenticateToken, (req, res) => {
  console.log('[API] 📚 获取系列作品 - 用户:', req.user.username);
  const series = [
    { icon: '🎬', name: '熊出没', desc: '原版系列，讲述熊大熊二与光头强在森林中的故事', year: '2012' },
    { icon: '🌍', name: '熊出没之环球大冒险', desc: '走出森林，来到城市和世界各地冒险', year: '2012' },
    { icon: '🌴', name: '熊出没之丛林总动员', desc: '回到丛林，继续保护森林的故事', year: '2013' },
    { icon: '🍂', name: '熊出没之秋日团团转', desc: '秋天的森林里发生的有趣故事', year: '2016' },
    { icon: '❄️', name: '熊出没之冬日乐翻天', desc: '冬天的森林充满欢乐与挑战', year: '2015' },
    { icon: '🌸', name: '熊出没之春日对对碰', desc: '春天来临，万物复苏的美好时光', year: '2014' }
  ];

  res.json({
    success: true,
    data: series
  });
});

app.get('/api/characters', authenticateToken, (req, res) => {
  console.log('[API] 🐻 获取角色信息 - 用户:', req.user.username);
  const characters = [
    {
      avatar: '🐻',
      name: '熊大',
      quote: '保护森林，熊熊有责！',
      description: '熊大是一头聪颖、智慧无边的雄性狗熊，懂得坚持主见的重要性，足智多谋，喜欢母熊翠花，常常为了讨好翠花与胞弟熊二互相竞争。',
      tags: ['聪明', '勇敢', '有责任心', '哥哥']
    },
    {
      avatar: '🐻',
      name: '熊二',
      quote: '俺的蜂蜜！',
      description: '熊二是一头憨厚可爱、力大无穷、比较聪明却好吃懒做的雄性狗熊，小动物们落难，熊二都会挺身而出，运用智慧打败光头强。熊二非常贪吃，最喜欢吃蜂蜜。',
      tags: ['憨厚', '可爱', '贪吃', '力气大']
    },
    {
      avatar: '🪓',
      name: '光头强',
      quote: '惹我光头强，熊熊变绵羊！',
      description: '光头强是一个伐木队的小老板，他带着李老板的重托来到风景优美的东北黑龙江省哈尔滨市原始森林里采伐原木，却不料平静的森林中原来隐藏着两个可怕的对手——森林的主人熊兄弟！',
      tags: ['聪明', '坚韧', '乐观', '多才多艺']
    },
    {
      avatar: '🦊',
      name: '小狸',
      quote: '大家都是好朋友嘛！',
      description: '小狸是一只温柔善良的小狐狸，她是熊大熊二的好朋友。小狸胆小但是热爱帮助别人，她害怕老鼠但是很勇敢地保护熊二的蜂蜜罐。',
      tags: ['善良', '温柔', '胆小', '友好']
    }
  ];

  res.json({
    success: true,
    data: characters
  });
});

app.get('/api/quotes', authenticateToken, (req, res) => {
  console.log('[API] 💬 获取经典台词 - 用户:', req.user.username);
  const quotes = [
    { text: '保护森林，熊熊有责！', author: '熊大' },
    { text: '惹我光头强，揍你没商量！', author: '光头强' },
    { text: '俺的蜂蜜！', author: '熊二' },
    { text: '熊就该有个熊样！', author: '熊大' },
    { text: '可恶的臭狗熊，我一定会回来的！', author: '光头强' },
    { text: '生活要有仪式感！', author: '光头强' }
  ];

  res.json({
    success: true,
    data: quotes
  });
});

app.get('/api/achievements', authenticateToken, (req, res) => {
  console.log('[API] 🏆 获取荣誉成就 - 用户:', req.user.username);
  const achievements = [
    '第十二届精神文明建设五个一工程优秀作品奖',
    '中国动漫金龙奖',
    '年度最佳电视动画奖',
    '年度最具产业价值动画奖',
    '白玉兰奖最佳动画片提名'
  ];

  res.json({
    success: true,
    data: achievements
  });
});

// ==================== 启动服务器 ====================
app.listen(PORT, () => {
  console.log('\n' + '='.repeat(60));
  console.log(`🚀 熊出没后端服务器启动成功！`);
  console.log(`📍 服务器地址: http://localhost:${PORT}`);
  console.log(`💾 使用纯JSON文件存储，无需编译！`);
  console.log('='.repeat(60));
  console.log('\n📋 可用API接口:');
  console.log('   POST /api/register        - 用户注册');
  console.log('   POST /api/login           - 用户登录');
  console.log('   POST /api/reset-password  - 重置密码（忘记密码）');
  console.log('   GET  /api/user/profile    - 获取用户信息（需Token）');
  console.log('   POST /api/user/change-password - 修改密码（需Token）');
  console.log('   GET  /api/videos          - 获取视频列表（需Token）');
  console.log('   GET  /api/series          - 获取系列作品（需Token）');
  console.log('   GET  /api/characters      - 获取角色信息（需Token）');
  console.log('   GET  /api/quotes          - 获取经典台词（需Token）');
  console.log('   GET  /api/achievements    - 获取荣誉成就（需Token）');
  console.log('\n👤 默认测试账号:');
  console.log('   用户名: admin');
  console.log('   密码:   123456');
  console.log('\n🔍 调试说明:');
  console.log('   所有操作都会输出详细日志，请查看后端控制台！');
  console.log('\n' + '='.repeat(60));
  console.log('服务器运行中，等待请求...\n');
});
