#!/bin/bash

echo "🛑 Зупинка старих контейнерів..."
docker-compose down --remove-orphans

echo "🧹 Збірка .jar..."
mvn clean package

echo "🚀 Запуск з пересборкою..."
docker-compose up --build