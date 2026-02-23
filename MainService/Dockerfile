# -------- Build stage --------
FROM mcr.microsoft.com/dotnet/sdk:10.0-preview AS build
WORKDIR /src

# Copy csproj and restore dependencies
COPY *.csproj .
RUN dotnet restore

# Copy everything else and publish
COPY . .
RUN dotnet publish -c Release -o /app/publish

# -------- Runtime stage --------
FROM mcr.microsoft.com/dotnet/aspnet:10.0-preview
WORKDIR /app

# Copy published output
COPY --from=build /app/publish .

# Expose container port
EXPOSE 8080

# Run the service
ENTRYPOINT ["dotnet", "MainService.dll"]
