# gofinder
Find secrets like api key, aws urls and emails on websites. This tool recieve input from stdin.

# How to install 
```go get github.com/noobexploiter/gofinder```

# How to use
```cat urls.txt | gofinder```
You can specify the threads using -t
```cat urls.txt | gofinder -t 64```
