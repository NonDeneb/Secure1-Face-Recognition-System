#!/usr/bin/env python
# -*- coding: utf-8 -*-

import os
import sys
import logging
from flask import Flask
from application.models import db, User

# 设置日志
logging.basicConfig(level=logging.DEBUG, 
                   format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# 创建测试应用
app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = "mysql+mysqldb://root:root@127.0.0.1:3306/face?charset=utf8"
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SQLALCHEMY_ECHO'] = True

# 初始化数据库
db.init_app(app)

def test_connection():
    """测试数据库连接"""
    with app.app_context():
        try:
            # 尝试查询用户表
            users = User.query.all()
            logger.info(f"查询到 {len(users)} 个用户")
            
            # 尝试创建测试用户
            test_user_id = "test_user_001"
            test_user = User.query.filter(User.user_id == test_user_id).first()
            
            if test_user is None:
                logger.info(f"创建测试用户: {test_user_id}")
                from datetime import datetime
                new_user = User(
                    user_status=1,
                    user_upload=1,
                    user_id=test_user_id,
                    create_time=datetime.now()
                )
                db.session.add(new_user)
                db.session.commit()
                logger.info("测试用户创建成功")
            else:
                logger.info(f"测试用户已存在: {test_user_id}")
                
            return True
        except Exception as e:
            logger.error(f"数据库连接测试失败: {str(e)}")
            return False

if __name__ == "__main__":
    if test_connection():
        print("数据库连接测试成功")
        sys.exit(0)
    else:
        print("数据库连接测试失败")
        sys.exit(1) 