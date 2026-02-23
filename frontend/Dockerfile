FROM node:20-alpine

WORKDIR /app

COPY package*.json ./
RUN npm install

COPY . .
RUN npm run build

EXPOSE 4173

# IMPORTANT: --host exposes to 0.0.0.0
CMD ["npm", "run", "preview", "--", "--host"]