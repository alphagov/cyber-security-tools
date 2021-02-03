# Logger

This module provides a JSON based log formatter. 

Log writes are augmented with information about the file, 
line number etc and you can make conventional placeholdered 
format string log writes or log complex data from a dictionary.

The goal is to be able to target components of log messages in 
splunk searches. 

So instead of `"user firstname.surname logged in at 18:00"` you 
have an event like: 

```
{
    "user": "firstname.surname",
    "action": "login", 
    "timestamp": "2020-11-18 18:00:00"
}
```  

So you can easily search for all `action=login` events or all 
activity by a given user ...

Because you've always got the reference back to where the 
event was created in the source code it's easy to debug and 
easy to find log writes to enrich if you need more detail.