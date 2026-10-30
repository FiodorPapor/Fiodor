FROM node:22-alpine AS build
WORKDIR /app
COPY package*.json ./
RUN npm ci --no-audit --no-fund
COPY . .
RUN npm run build \
 && find dist/assets -maxdepth 1 -type f -exec basename {} \; | sort > dist/release-assets.txt \
 && test -s dist/release-assets.txt \
 && if [ -d .deploy-legacy/assets ]; then cp -a .deploy-legacy/assets/. dist/assets/; fi

FROM nginx:1.27-alpine
COPY nginx/default.conf.template /etc/nginx/templates/default.conf.template
ENV API_UPSTREAM=property-intent-api:8080
COPY --from=build /app/dist /usr/share/nginx/html
