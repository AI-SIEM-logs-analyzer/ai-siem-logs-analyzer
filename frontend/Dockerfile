# Stage 1: Build
FROM node:22-alpine AS build

WORKDIR /app

# Enable pnpm matching project packageManager
RUN corepack enable && corepack prepare pnpm@9.15.4 --activate

# Copy package files first to cache dependency installation
COPY package.json pnpm-lock.yaml ./

# Install dependencies
RUN pnpm install --frozen-lockfile

# Copy project source
COPY . .

# Build production bundle
RUN pnpm build

# Stage 2: Serve with Nginx
FROM nginx:alpine

COPY --from=build /app/dist /usr/share/nginx/html
COPY nginx.conf /etc/nginx/conf.d/default.conf

EXPOSE 80

CMD ["nginx", "-g", "daemon off;"]
