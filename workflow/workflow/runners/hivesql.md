执行HIVE sql脚本

### 功能说明
执行一个sql 脚本，系统不会对hive sql进行语法检查。

### 其他说明
hive sql脚本执行者为任务第一个责任人（portal登录用户)

### 任务设置
#### 1. 基本信息  
参考 [基本信息设置](/workflow/workflow/runnerBasicInfo.md)  
#### 2. 调度  
参考 [调度设置](/workflow/workflow/runnerCycle.md)  

#### 3. 参数
###### 3.1 源服务器配置信息  
执行hive sql 脚本所在的hive server.  
更多信息参考 [服务器配置](/workflow/services/readme.md)

###### 3.2 SQL文件
务必确保任务的第一责任人能够访问，hive sql 文件中提到的hive 表，否则会提示权限异常。  
如果hive sql 中有复杂的hive sql ，提交yarn 上是用的工作流所在项目对应的资源池。 
sql 脚本中可以使用时间参数 ``` ${YYYYMMDDHH}  ``` ,会将实例的数据时间替换sql 脚本中的时间参数。  
支持的格式有：
```
${YYYY} 年
${YYYYMM} 月
${YYYYMMDD} 日
${YYYYMMDDHH} 小时
${YYYYMMDDHHFF} 分钟
```

### demo
hive sql 文件内容：
```
use demoDB;
show tables;
```

### demo资源