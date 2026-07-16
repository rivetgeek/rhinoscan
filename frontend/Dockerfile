FROM node:20-alpine AS build
WORKDIR /app
COPY package.json package-lock.json* ./
RUN npm install
COPY . .
RUN npm run build

FROM nginx:alpine
COPY --from=build /app/dist /usr/share/nginx/html
# Placed in templates/ so the nginx entrypoint envsubsts ${RHINOSCAN_API_TOKEN}
# (and only defined env vars — nginx's own $vars are untouched) into
# /etc/nginx/conf.d/default.conf at container start.
COPY nginx.conf /etc/nginx/templates/default.conf.template
EXPOSE 3000
