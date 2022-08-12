## Installation

1. 确保已经安装 python3.8 Postgresql数据库、nmap
2. 安装系统运行所需要的依赖
```

$pip install -r requirements.txt

```

3. 修改conf/config文件中的路径内容
（1） 修改NMAP Script的 路径， 将下述的路径修改为部署的NMap的路径
NMAP_SCRIPT_PATH = '/opt/homebrew/Cellar/nmap/7.92/share/nmap/scripts' 
（2）修改 数据库连接
chunyu 替换为你的用户名
如果有密码的话，那就写成 用户名:密码的形式
@后面修改数据库的地址。
所以最终的URI的表示形式为：
postgres://用户名：密码@数据库地址：端口号/数据库名

SQLALCHEMY_DATABASE_URI = 'postgresql://chunyu@localhost:5432/iot'

4. 运行程序，进入到本程序的根目录，执行python run.py就应该可以运行整个系统了


``` 修改conf文件夹中config内的部分内容，具体请查看，```

## Executing the sample

* Execute - ```python run.py```
* Load browser at ```http://localhost:5000/```

## 2022.05.08 如何创建自己的model以及代码

这个里面的代码包含了我以前写的，大家目前可以忽略，我们这次所有的代码均写在controller文件夹以及models文件夹。

只需要参考一下models里面如何创建数据库表，以及handlers/finger如何创建service以及view即可。

1. 所有的数据库表创建在models文件夹内，每个文件夹内也有readme文件，可以参考

关于SQL，可以参考https://flask-sqlalchemy.palletsprojects.com/en/2.x/

2. 对于nmap scan，在controller文件夹内创建自己对应的文件夹，参考内部的readme文件

3. 当需要运行自己的程序时，对于nmap scan这部分。可以参考controller文件夹内的readme， 对于创建数据库表以及写业务逻辑的两位同学，需要同样的在controller文件夹内，创建一下自己的模块，然后通过浏览器进行调用和测试。
