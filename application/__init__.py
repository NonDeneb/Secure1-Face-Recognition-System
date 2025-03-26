# -*- coding: utf-8 -*-

import os
import time
import base64
import string
import random
import config
from flask import Flask, make_response
from flask_wtf.csrf import CSRFProtect
from application.models import User, db
from application.exts import allowed_file, get_origin_data, get_encrypt_data
from application.face_data import get_user_data
from application.detect import load_and_detect_data
from application.util import face_compares, gen_user_key, data_encrypt
from flask import render_template, request, jsonify, session, redirect
import sys
import json
import numpy as np
import tensorflow as tf
import logging
from datetime import datetime
import math

# 设置日志级别为DEBUG
logging.basicConfig(level=logging.DEBUG, 
                   format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# 检查TensorFlow版本
tf_version = tf.__version__
is_tf2 = tf_version.startswith('2.')
logger.info(f"TensorFlow版本: {tf_version}")

# 适配TensorFlow 2.x
if is_tf2:
    import tensorflow.compat.v1 as tf_compat
    tf_compat.disable_eager_execution()

def create_app():
    app = Flask(__name__)  # type: Flask
    app.config.from_object(config)
    app.config.from_pyfile('../config.py')
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
    app.config['UPLOAD_FOLDER'] = './upload'
    app.debug = True
    
    # 打印数据库配置信息
    db_uri = app.config.get('SQLALCHEMY_DATABASE_URI', 'Not configured')
    logger.info(f"数据库URI: {db_uri}")
    logger.info(f"SQLALCHEMY_TRACK_MODIFICATIONS: {app.config['SQLALCHEMY_TRACK_MODIFICATIONS']}")
    
    # 确保上传文件夹存在
    if not os.path.exists(app.config['UPLOAD_FOLDER']):
        os.makedirs(app.config['UPLOAD_FOLDER'])
        logger.info(f"创建上传文件夹: {app.config['UPLOAD_FOLDER']}")

    try:
        db.init_app(app)
        logger.info("数据库初始化成功")
    except Exception as e:
        logger.error(f"数据库初始化失败: {str(e)}")
        
    CSRFProtect(app)
    return app


app = create_app()


# 首页
@app.route('/')
def index():
    logger.info("进入首页路由")
    need_create_user = False
    
    if request.cookies.get('user_id') is not None:
        session['user_id'] = request.cookies.get('user_id')
        logger.info(f"从Cookie获取用户ID: {session['user_id']}")
    elif session.get('user_id') is None:
        session.permanent = True
        session['user_id'] = time.strftime("%Y%m%d%H%M%S", time.localtime()) + ''.join(
            random.choices(string.ascii_letters + string.digits, k=15))
        logger.info(f"生成新的用户ID: {session['user_id']}")
        need_create_user = True
    
    # 检查数据库中是否存在该用户，不存在则创建
    try:
        user = User.query.filter(User.user_id == session['user_id']).first()
        if user is None:
            logger.info(f"用户 {session['user_id']} 不存在，创建新用户")
            new_user = User(
                user_id=session['user_id'],
                user_status=0, 
                user_upload=0, 
                create_time=datetime.now()
            )
            db.session.add(new_user)
            db.session.commit()
            logger.info(f"新用户创建成功: {session['user_id']}")
    except Exception as e:
        logger.error(f"检查/创建用户异常: {str(e)}")
    
    response = make_response(render_template('index.html'))
    response.set_cookie('user_id', session['user_id'], max_age=7*24*3600)  # 7天有效期
    return response


# 录入
@app.route('/gain')
def gain():
    if session.get('user_id') is None:
        return redirect('/')
    return render_template('gain.html')


# 信息
@app.route('/info')
def information():
    if session.get('user_id') is None:
        return redirect('/')
    img_status = False
    user_img = ''
    if os.path.exists("./upload/%s.old.png" % session.get('user_id')):
        user_img = '/upload/' + session.get('user_id') + '.old.png'
        img_status = True
    return render_template('info.html', user_id=session.get('user_id'), user_img=user_img, img_status=img_status)


# 数据页面
@app.route('/data')
def data_page():
    if session.get('user_id') is None:
        return redirect('/')
    img_status = False
    user_img = ''
    if os.path.exists("./upload/%s.old.png" % session.get('user_id')):
        user_img = '/upload/' + session.get('user_id') + '.old.png'
        img_status = True
    return render_template('data.html', user_id=session.get('user_id'), user_img=user_img, img_status=img_status)


# 关于
@app.route('/about')
def about():
    return render_template('about.html')


# 获取照片
@app.route('/upload/<filename>', methods=['GET'])
def upload(filename):
    user_id = session.get('user_id')
    req_user_id = request.cookies.get('user_id')
    if user_id is None:
        return redirect('/')
    if user_id + '.old.png' != filename:
        return redirect('/')
    if req_user_id is None:
        return redirect('/')
    if req_user_id + '.old.png' != filename:
        return redirect('/')
    if os.path.exists("./upload/%s" % filename):
        file = os.path.join('./upload', filename)
        with open(file, 'rb') as f:
            img = f.read()
        return img
    return render_template('404.html'), 404


# 文件上传接口
@app.route('/file_upload', methods=['POST'])
def file_upload():
    if 'file' not in request.files:
        return jsonify('false'), 403
    res = {'code': 0, 'msg': '禁止'}
    user_id = session.get('user_id')
    image = request.files['file']
    header_type = request.headers.get('Type')
    key_res = False

    if image and allowed_file(image.filename):
        img_path = './upload/' + user_id + '.png'
        if header_type == '1':
            img_path = './upload/' + user_id + '.old.png'
            # 生成key
            key_res = gen_user_key(user_id)
        if header_type == '2':
            img_path = './upload/' + user_id + '.new.png'
        try:
            image.save(os.path.join(img_path))
        except Exception as e:
            print(e)
            res['msg'] = '系统错误0'
            return jsonify(res), 200
        # 人脸有无判断
        try:
            result = load_and_detect_data([img_path], 1.0)
        except Exception as e:
            print(e)
            res['msg'] = '系统错误1'
            return jsonify(res), 200
        if result == 0:
            os.remove(img_path)
            res['msg'] = '未识别到人脸'
            return jsonify(res), 200
        if header_type == '1' and not key_res:
            res = {'code': 0, 'msg': '密钥生成失败'}
            return jsonify(res), 200
        # 数据入库
        db_res = User.query.filter(User.user_id == user_id).first()
        if db_res is None:
            user = User(user_status=1, user_id=user_id, user_upload=1,
                        create_time=time.strftime('%Y-%m-%d %H:%M:%S', time.localtime()))
            db.session.add(user)
            db.session.commit()
        elif header_type == '1':
            user = User.query.filter(User.user_id == user_id).first()
            user.user_upload += 1
            user.user_status = 1
            db.session.add(user)
            db.session.commit()
        res['code'] = 1
        res['msg'] = '上传成功'
        res['user_id'] = user_id
        return jsonify(res), 200
    else:
        return jsonify(res), 200


# 拍照上传接口
@app.route('/img_upload', methods=['POST'])
def img_upload():
    logger.info("进入图片上传处理函数")
    try:
        data = request.form
        user_id = data.get('user_id')
        base64_image = data.get('image')
        
        if user_id is None:
            logger.error("用户ID为空")
            return jsonify({"status": 0, "msg": "用户ID为空"})
        if base64_image is None:
            logger.error("图片数据为空")
            return jsonify({"status": 0, "msg": "图片数据为空"})
            
        logger.info(f"处理用户ID: {user_id}")
        
        try:
            # 查询数据库中是否存在该用户
            logger.info("查询数据库中是否存在该用户")
            db_res = User.query.filter(User.user_id == user_id).first()
            logger.info(f"数据库查询结果: {db_res}")
            
            if db_res is None:
                logger.error(f"用户 {user_id} 不存在")
                return jsonify({"status": 0, "msg": "用户不存在"})
                
            # 保存图片
            img_path = './upload/' + user_id + '.old.png'
            base64_image = base64_image.replace('data:image/png;base64,', '')
            with open(img_path, "wb") as file:
                decode_base64 = base64.b64decode(base64_image)
                file.write(decode_base64)
                
            # 人脸检测
            try:
                result = load_and_detect_data([img_path], 1.0)
                if result == 0:
                    os.remove(img_path)
                    return jsonify({"status": 0, "msg": "未识别到人脸"})
            except Exception as e:
                logger.error(f"人脸检测失败: {str(e)}")
                return jsonify({"status": 0, "msg": "人脸检测失败"})
                
            # 生成密钥
            if not gen_user_key(user_id):
                return jsonify({"status": 0, "msg": "密钥生成失败"})
                
            # 更新用户状态
            user = User.query.filter(User.user_id == user_id).first()
            user.user_upload += 1
            user.user_status = 1
            db.session.commit()
            
            logger.info("图片上传处理成功")
            return jsonify({"status": 1, "msg": "上传成功", "user_id": user_id})
            
        except Exception as e:
            logger.error(f"数据库操作异常: {str(e)}")
            return jsonify({"status": 0, "msg": f"数据库错误: {str(e)}"})
            
    except Exception as e:
        logger.error(f"图片上传处理异常: {str(e)}")
        return jsonify({"status": 0, "msg": f"系统错误: {str(e)}"})


# 脸部比较
@app.route('/face_compare', methods=['POST'])
def face_compare():
    res = {'code': 0, 'msg': '禁止'}
    user_id = session.get('user_id')
    req_user_id = request.cookies.get('user_id')
    if user_id is None:
        return jsonify(res), 200
    if req_user_id is None:
        return jsonify(res), 200
    if user_id != req_user_id:
        res['msg'] = 'ID不一致，请刷新后重新上传'
        return jsonify(res), 200
    if request.form['user_id'] is None:
        res['msg'] = '请刷新后重试'
        return jsonify(res), 200
    if request.form['user_id'] != user_id:
        res['msg'] = 'ID不一致，请刷新后重新上传'
        return jsonify(res), 200
    origin_res = os.path.exists('./application/data/originUserFaceData/%s.old.txt' % user_id)
    try:
        user = User.query.filter(User.user_id == session.get('user_id')).first()
        # 如果已经获取过原始数据 则设置过session['upload_times'] 此时不需要运行获取原始数据 反之则需要
        # 如果又上传了一次照片 则session['upload_times']中的数据应小于数据库中的值 需要运行数据
        if session.get('upload_times') is None or user.user_upload > session.get('upload_times') or not origin_res:
            origin_res = get_user_data(user_id, 'old')
            session['upload_times'] = user.user_upload
        if session.get('upload_times') == user.user_upload and user.user_status >= 3 and os.path.exists(
                './application/data/encryptUserFaceData/%s.old' % user_id):
            encrypt_res = True
        else:
            encrypt_res = data_encrypt(user_id, 'old')
        origin_new_res = get_user_data(user_id, 'new')
        encrypt_new_res = data_encrypt(user_id, 'new')
    except Exception as e:
        print(e)
        res['msg'] = '系统错误2'
        return jsonify(res), 200
    if origin_new_res and encrypt_new_res and origin_res and encrypt_res:
        print("=========== 开始人脸比对 ===========")
        print(f"用户ID: {user_id}")
        print(f"加密旧数据路径: ./application/data/encryptUserFaceData/{user_id}.old")
        print(f"加密新数据路径: ./application/data/encryptUserFaceData/{user_id}.new")
        print(f"密钥路径: ./application/data/userKey/{user_id}.sk")
        
        # 检查文件存在
        old_data_exists = os.path.exists(f'./application/data/encryptUserFaceData/{user_id}.old')
        new_data_exists = os.path.exists(f'./application/data/encryptUserFaceData/{user_id}.new')
        sk_exists = os.path.exists(f'./application/data/userKey/{user_id}.sk')
        relin_exists = os.path.exists(f'./application/data/userKey/{user_id}.re')
        galois_exists = os.path.exists(f'./application/data/userKey/{user_id}.ga')
        
        print(f"文件检查 - 加密旧数据是否存在: {old_data_exists}")
        print(f"文件检查 - 加密新数据是否存在: {new_data_exists}")
        print(f"文件检查 - 私钥是否存在: {sk_exists}")
        print(f"文件检查 - 重线性化密钥是否存在: {relin_exists}")
        print(f"文件检查 - Galois密钥是否存在: {galois_exists}")
        
        result = face_compares(user_id)
        print('识别结果:', result, type(result))
        # 关键判断部分
        try:
            # 确保result是有效的数值
            if isinstance(result, (int, float)) and not math.isnan(result):
                formatted_result = "%.4f" % result
            else:
                formatted_result = "0.0000"
                print(f"警告：相似度结果无效: {result}，使用默认值0")
                
            if result < 0.6:
                res['code'] = 2
                res['msg'] = '认证失败'
                res['data'] = formatted_result
            else:
                res['code'] = 1
                res['msg'] = '识别成功'
                res['data'] = formatted_result
            
            print(f"最终返回给前端的数据: {res}")
        except Exception as e:
            print(f"处理相似度时出错: {e}")
            res['code'] = 2
            res['msg'] = '处理相似度时出错'
            res['data'] = "0.0000"
    else:
        print(f"数据准备阶段检查 - 原始旧数据: {origin_res}, 加密旧数据: {encrypt_res}, 原始新数据: {origin_new_res}, 加密新数据: {encrypt_new_res}")
        if not origin_res:
            print("原始旧数据准备失败")
        if not encrypt_res:
            print("加密旧数据准备失败")
        if not origin_new_res:
            print("原始新数据准备失败")
        if not encrypt_new_res:
            print("加密新数据准备失败")
    return jsonify(res), 200


# 原始数据处理
@app.route('/origin_data', methods=['POST'])
def origin_data():
    res = {'code': 0, 'msg': '禁止'}
    user_id = session.get('user_id')
    req_user_id = request.cookies.get('user_id')
    if user_id is None:
        return jsonify(res), 200
    if req_user_id is None:
        return jsonify(res), 200
    if user_id != req_user_id:
        res['msg'] = 'ID不一致，请刷新后重新上传'
        return jsonify(res), 200
    origin_res = os.path.exists('./application/data/originUserFaceData/%s.old.txt' % user_id)
    try:
        user = User.query.filter(User.user_id == user_id).first()
        if session.get('upload_times') is None or user.user_upload > session.get('upload_times'):
            origin_res = get_user_data(user_id, 'old')
            session['upload_times'] = user.user_upload
        elif session.get('upload_times') == user.user_upload and user.user_status >= 2 and origin_res:
            res['code'] = 1
            res['msg'] = '成功'
            res['data'] = get_origin_data(user_id)
            return jsonify(res), 200
    except Exception as e:
        print(e)
        res['msg'] = '系统错误3'
        return jsonify(res), 200
    if origin_res:
        try:
            update = User.query.filter(User.user_id == user_id).first()
            update.user_status = 2
            db.session.commit()
        except Exception as e:
            print(e)
            res['msg'] = '系统错误4'
            return jsonify(res), 200
        res['code'] = 1
        res['msg'] = '成功'
        res['data'] = get_origin_data(user_id)
        return jsonify(res), 200
    res['msg'] = '数据已经处理或系统错误'
    return jsonify(res), 200


# 处理加密数据
@app.route('/encrypt_data', methods=['POST'])
def encrypt_data():
    res = {'code': 0, 'msg': '禁止'}
    user_id = session.get('user_id')
    req_user_id = request.cookies.get('user_id')
    if user_id is None:
        return jsonify(res), 200
    if req_user_id is None:
        return jsonify(res), 200
    if user_id != req_user_id:
        res['msg'] = 'ID不一致，请刷新后重试'
        return jsonify(res), 200

    try:
        user = User.query.filter(User.user_id == user_id).first()
        # 如果upload_times为None 或着用户又上传了一次则说明需要获取一次原数据
        if session.get('upload_times') is None or user.user_upload > session.get('upload_times'):
            get_user_data(user_id, 'old')
            session['upload_times'] = user.user_upload
            user.user_status = 2
        # 如果已经有了加密数据
        encrypt_res = os.path.exists('./application/data/encryptUserFaceData/%s.old' % user_id)
        if session.get('upload_times') == user.user_upload and user.user_status >= 3 and encrypt_res:
            res['code'] = 1
            res['msg'] = '成功'
            res['data'] = get_encrypt_data(user_id)
            return jsonify(res), 200
        # 如果没有加密数据，则需要加密数据计算
        origin_res = os.path.exists('./application/data/originUserFaceData/%s.old.txt' % user_id)
        if session.get('upload_times') == user.user_upload and user.user_status >= 2 and origin_res:
            encrypt_res = data_encrypt(user_id, 'old')
            user.user_status = 3
        db.session.commit()
    except Exception as e:
        print(e)
        res['msg'] = '系统错误5'
        return jsonify(res), 200
    if encrypt_res:
        res['code'] = 1
        res['msg'] = '成功'
        res['data'] = get_encrypt_data(user_id)
        return jsonify(res), 200
    return jsonify(res), 200


# 自定义404模板
@app.errorhandler(404)
def page_not_found(e):
    return render_template('404.html'), 404


# 自定义500模板
@app.errorhandler(500)
def internal_server_error(e):
    return render_template('500.html'), 500


# 创建用户人脸数据文件夹
if not os.path.exists('./application/data'):
    os.makedirs('./application/data')
if not os.path.exists('./application/data/originUserFaceData'):
    os.makedirs('./application/data/originUserFaceData')
if not os.path.exists('./application/data/encryptUserFaceData'):
    os.makedirs('./application/data/encryptUserFaceData')


def calc_sum(A, B):
    """ 计算两个向量的内积 """
    return np.sum(np.multiply(A, B))

def calc_denom(A, B):
    """ 计算向量的模长(欧氏距离) """
    return np.sqrt(calc_sum(A, A)) * np.sqrt(calc_sum(B, B))

def calc_cos(A, B):
    """ 计算两个向量的余弦值 """
    num = calc_sum(A, B)
    denom = calc_denom(A, B)
    return num / denom

def distance(A, B):
    """ 计算人脸距离，这里是向量的欧式距离 """
    # 使用向量的余弦值距离
    # cosValue = calc_cos(A,B)
    # return np.arccos(cosValue)/np.pi
    
    # 使用向量的欧氏距离
    
    # print('A:',A)
    # print('\nB:',B)
    # t1 = sum([(a - b)**2 for (a,b) in zip(A,B)])
    # t2 = np.sqrt(t1)
    # print('计算结果:',t2)
    return np.sqrt(sum([(a - b)**2 for (a, b) in zip(A, B)]))

def saveImage(file, filename, type):
    """ 保存图片到本地 """
    if file.filename == '':
        # print("文件名为空")
        return False
    if file and allowed_file(file.filename):
        # 安全获取文件名
        # filename = secure_filename(file.filename)
        filePath = os.path.join(app.config['UPLOAD_FOLDER'], filename + '.' + type + '.png')
        file.save(filePath)
        # print('图片保存成功')
        return True
    else:
        # print('出错了')
        return False

def allowedFile(filename):
    """ 允许的文件后缀名 """
    ALLOWED_EXTENSIONS = set(['png', 'jpg', 'jpeg'])
    return '.' in filename and \
           filename.rsplit('.', 1)[1] in ALLOWED_EXTENSIONS

def getfaceVector(token, type):
    """ 获取人脸特征向量，
    type=register/encrypt/check
    token是人脸图像文件名
    """
    if type == 'register' or type == 'check':
        # 明文数据路径
        dataPath = os.path.join('./application/data/originUserFaceData', token + '.' + type + '.txt')
        if type == 'register':
            # 根据uid从数据库中获取数据
            user = User.query.filter(User.user_id == token).first()
            # print('获取数据库中保存的用户人脸数据')
            if not user: return False
            return np.array(json.loads(user.faceData))
        # print('获取本地明文人脸文件数据:',dataPath)
        origin_data = np.loadtxt(dataPath)
        return origin_data
    else:
        # 密文数据路径
        encrypt_dataPath = os.path.join('./application/data/encryptUserFaceData', token + '.encrypt.txt')
        encrypt_data = np.loadtxt(encrypt_dataPath)
        return encrypt_data

# 注册模板过滤器
@app.template_filter('base64')
def base64Filter(content):
    return base64.b64encode(content).decode('ascii')


@app.template_filter('strftime')
def strftimeFilter(date, format="%Y-%m-%d %H:%M:%S"):
    return date.strftime(format)


user_distance = 1.0
