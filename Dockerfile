# backend/Dockerfile

FROM node:18 AS base

WORKDIR /app

# Copy package files and install dependencies
COPY package*.json ./
RUN npm install

# Copy the rest of the app source
COPY . .

# Expose the backend port
EXPOSE 3001

# Run the development server
CMD ["npm", "run", "start:dev"]
