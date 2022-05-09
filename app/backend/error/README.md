### Introduction


error 用于处理全局错误信息，通过在apiexception中定义对应的错误代码以及错误信息，进而支持当程序运行错误，或者需要向用户端返回错误信息时，可以以统一的格式返回信息。

当需要定义错误类型时，可以更改apiexception中内容，以如下格式即可

```
class ServerError(APIException):
    code = 500
    msg = 'sorry, we made a mistake!'
    error_code = 999
```
