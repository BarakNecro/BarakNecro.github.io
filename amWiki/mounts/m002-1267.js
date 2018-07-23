if(typeof AWPageMounts=='undefined'){AWPageMounts={}};AWPageMounts['m002']=[{"name":"001-通用API接口文档示例.md","path":"002-文档示范/001-通用API接口文档示例.md","content":"# 客户日志流水接口示例\r\n>维护人员：**Tevin**  \r\n>创建时间：2016-04-06\r\n\r\n## 接口简介\r\n实时查询客户各种操作(例如登录，拓客等)的流水日志  \r\n\r\n## 接口详情\r\n\r\n### 请求地址\r\n/api/customer-flow\r\n\r\n### 请求类型\r\nGET\r\n\r\n### 请求参数\r\n| 参数名 | 类型 | 必填 | 描述 | 默认值 | 参考值 |\r\n| --- | :---: | :---: | --- | --- | --- |\r\n| customer_id | number | 是 | 客户id | - | 132 |\r\n| type | number | 否 | 客户类型，0所有、1扩展、2报备、3成交 | - | 1 |\r\n\r\n### 返回正确JSON示例\r\n```javascript\r\n{\r\n    \"state\": {\r\n        \"code\": 10200,\r\n        \"msg\": \"ok\"\r\n    },\r\n    \"data\": {\r\n        \"id\": 307,  //流水id\r\n        \"real_name\": \"Tevin\",  //用户名称\r\n        \"mobile\": \"暂无\",  //用户手机\r\n        \"origin\": \"暂无\",  //用户来源\r\n        \"created_at\": \"2016-04-04 20:00:00\",  //加入时间\r\n        \"last_login\": \"2016-05-22 15:30:21\",  //最后登录时间\r\n        \"log\": []  //日志列表\r\n    }\r\n}\r\n```\r\n### 返回错误JSON示例\r\n```javascript\r\n{\r\n    \"state\": {\r\n        \"code\": 10500\r\n        \"msg\": \"服务器未知报错\"\r\n    }\r\n}\r\n```\r\n\r\n### 备注说明\r\n无\r\n\r\n### 修改日志\r\n- 【2016-05-22】  \r\n   新增了last_login最后登录时间字段\r\n","timestamp":1532319884863}]