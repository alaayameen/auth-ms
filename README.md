# auth-ms-v1

[![Build Status](https://travis-ci.org/codecentric/springboot-sample-app.svg?branch=master)](https://travis-ci.org/codecentric/springboot-sample-app)


## Requirements

For building and running the application you need:

- [JDK 1.8](http://www.oracle.com/technetwork/java/javase/downloads/jdk8-downloads-2133151.html)
- [Maven 3](https://maven.apache.org)
- [MongoDB 4.4.5](https://docs.mongodb.com/manual/release-notes/4.4/#release-notes-for-mongodb-4.4)

## starting MongoDB locally

1- Start MongoDB without access control.
`mongod --port 27017 --dbpath /data/db1`

2-  Connect to the instance.
`mongo --port 27017`

3- Create the user administrator.

`use admin`

`db.createUser ({
"user":"appMongoDB",
"pwd":"12345",
"roles": [
{ "role":"userAdminAnyDatabase", "db":"admin" }
]
})
`

4- Re-start the MongoDB instance with access control.
`mongod --auth --port 27017 --dbpath /data/db1`

5- Authenticate as the user administrator.
`mongo --port 27017 -u "appMongoDB"  -p "123"  --authenticationDatabase "admin"`

## Running the application locally

There are several ways to run a Spring Boot application on your local machine. One way is to execute the `main` method in the `de.codecentric.springbootsample.Application` class from your IDE.

Alternatively you can use the [Spring Boot Maven plugin](https://docs.spring.io/spring-boot/docs/current/reference/html/build-tool-plugins-maven-plugin.html) like so:

```shell
mvn spring-boot:run
```
