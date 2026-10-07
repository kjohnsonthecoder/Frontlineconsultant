FROM node:24-bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends gosu && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY package.json server.mjs scan.mjs model.mjs test.mjs bridge-test.mjs base44-bridge.mjs ./
RUN npm test
COPY entrypoint.sh /app/entrypoint.sh
RUN mkdir /data && chown node:node /data
ENV PORT=8080 FRONTLINE_DB_PATH=/data/frontline.sqlite
EXPOSE 8080
ENTRYPOINT ["sh","/app/entrypoint.sh"]
CMD ["node","server.mjs"]
