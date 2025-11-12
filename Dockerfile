FROM node:20-alpine
WORKDIR /app
COPY package.json package-lock.json* ./
RUN npm install --omit=dev || npm install
COPY server.mjs ./
EXPOSE 8080
CMD ["node", "server.mjs"]