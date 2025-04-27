# Start from lightweight Node.js Alpine base image
FROM node:18-alpine

# Set environment variables
ENV NODE_ENV=production
ENV PORT=3000

# Set working directory inside container
WORKDIR /usr/src/app

# Install app dependencies
COPY package*.json ./
RUN npm install --frozen-lockfile --production

# Copy the rest of the application source code
COPY . .

# Expose the app port
EXPOSE 3000

# By default, start as root to fix permissions inside container
USER root

# Final command
CMD sh -c "chown -R node:node /usr/src/app/data && su node -c 'node src/server.js'"
