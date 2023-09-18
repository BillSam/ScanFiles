# prepare

mvn clean install
mvn clean compile package

# Docker Commands

docker build -t clamav-scanner .

docker image ls -a | grep clamav-scanner

docker run -p 8080:8080  clamav-scanner

http://localhost:8080/swagger-ui.html
