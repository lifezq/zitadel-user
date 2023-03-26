FROM banbushi/public:centos7.9-jdk1.8.0_144
ENV PORT=18080
ADD web/target/web-*.jar /opt/web.jar
CMD ["sh","-c","java $JAVA_OPTS -Xms256m -Xmx1024m -XX:MetaspaceSize=128m -XX:MaxMetaspaceSize=512m -jar /opt/web.jar --server.port=$PORT"]
WORKDIR /opt
EXPOSE 18080