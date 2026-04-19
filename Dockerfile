FROM nginx:alpine

RUN apk add --no-cache python3

COPY checker.py         /app/checker.py
COPY config.json        /app/config.json
COPY start.sh           /app/start.sh
COPY nginx.conf         /etc/nginx/conf.d/default.conf
COPY homelab-map.html   /usr/share/nginx/html/index.html

RUN chmod -R 755 /usr/share/nginx/html && \
    chmod +x /app/start.sh

VOLUME ["/data"]

EXPOSE 80

# docker run -v /var/run/docker.sock:/var/run/docker.sock:ro -v homelab-data:/data -p 8080:80 homelab-site

CMD ["/app/start.sh"]
