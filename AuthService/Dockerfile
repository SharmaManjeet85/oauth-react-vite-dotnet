# -------- Build stage --------
FROM mcr.microsoft.com/dotnet/sdk:10.0-preview AS build
WORKDIR /src

# Copy project file and restore
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

# ASP.NET default port
EXPOSE 8080

# IMPORTANT: update DLL name if needed
ENTRYPOINT ["dotnet", "AuthService.dll"]