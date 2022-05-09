

在本文件内创建对各个表的增删改查语句，Flask SQL 支持对表的查找、添加等操作，但是有时候我们需要自定义一些SQL以及写一些复杂的SQL，那么就在这个文件夹里面创建对每个表的操作文件。



E.g. 对deviceInfo表进行操作，则创建deviceInfoDao.py 文件，并在里面写对应的函数以及代码

关于如何调用程序写代码，可以参考下面的document
https://flask-sqlalchemy.palletsprojects.com/en/2.x/