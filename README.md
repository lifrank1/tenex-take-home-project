# Cybersecurity Log Analysis Platform

A full-stack web application for analyzing ZScaler web proxy logs and providing SOC analysts with actionable security insights.

## Tech Stack

### Frontend
- **Next.js 14** with App Router
- **TypeScript** for type safety
- **Tailwind CSS** for styling
- **Lucide React** for icons
- **React Dropzone** for file uploads

### Backend
- **Express.js** REST API
- **TypeScript** for type safety
- **Prisma** ORM for database operations
- **PostgreSQL** database
- **JWT** authentication
- **Multer** for file uploads

## Project Structure

```
tenexfinal/
├── frontend/          # Next.js application
│   ├── src/
│   │   ├── app/      # App router pages
│   │   ├── components/ # React components
│   │   └── contexts/  # React contexts
├── backend/           # Express.js API server
│   ├── src/
│   │   ├── routes/   # API routes
│   │   ├── middleware/ # Express middleware
│   │   ├── services/ # Business logic
│   │   ├── types/    # TypeScript types
│   │   └── utils/    # Utility functions
│   └── prisma/       # Database schema
├── shared/            # Shared types between frontend/backend
└── README.md
```

## Packages

- Node.js 18+ 
- PostgreSQL 12+
- npm or yarn

## Setup Instructions

### 1. Clone the Repository

```bash
git clone <repository-url>
cd tenexfinal
```

### 2. Set up PostgreSQL Database

Create a new PostgreSQL database:

```sql
CREATE DATABASE tenex_logs;
CREATE USER tenex_user WITH PASSWORD 'your_password';
GRANT ALL PRIVILEGES ON DATABASE tenex_logs TO tenex_user;
```

### 3. Backend Setup

```bash
cd backend

# Install dependencies
npm install

# Set up environment variables
cp .env.example .env
# Edit .env with your database credentials

# Generate Prisma client
npm run db:generate

# Push database schema
npm run db:push

# Start development server
npm run dev
```

The backend will run on `http://localhost:3001`

### 4. Frontend Setup

```bash
cd frontend

# Install dependencies
npm install

# Start development server
npm run dev
```

The frontend will run on `http://localhost:3000`

### 5. Verify Installation

1. **Backend**: Check `http://localhost:3001` - should show "Server running on port 3001"
2. **Frontend**: Check `http://localhost:3000` - should show the TENEX.AI login page
3. **Database**: Backend should show "Database connected successfully"

### 6. First Run

1. Open `http://localhost:3000` in your browser
2. Register a new account
3. Upload a sample log file (see Sample Log Format section below)
4. Monitor the processing and view results

## Anomaly Detection

TENEX.AI includes basic anomaly detection focused on identifying potential security issues in log data:

### **Currently Implemented Detectors**

#### **1. URL Pattern Analysis** 🔍
**What it does:** Flags URLs accessed more than 2x the average access rate
**Code logic:** 
```typescript
// Calculates average requests per URL across all URLs
const avgAccessPerURL = entries.length / urlPatterns.size;

// Flags if: URL access count > (average × 2)
if (pattern.count > avgAccessPerURL * 2) {
  // Triggers anomaly
}
```
**Example:** If most URLs get 10 hits, but one URL gets 25+ hits → anomaly

#### **2. User Agent Analysis** 🤖
**What it does:** Detects known scanning tools and automation frameworks
**Code logic:**
```typescript
const suspiciousPatterns = [
  /bot/i, /crawler/i, /spider/i, /scraper/i,
  /curl/i, /wget/i, /python/i, /java/i,
  /sqlmap/i, /nikto/i, /nmap/i, /metasploit/i
];
```
**Example:** User agent contains "sqlmap" or "nmap" → anomaly

#### **3. Geographic Access** 🌍
**What it does:** Flags countries with 2x more unique IPs than average
**Code logic:**
```typescript
const avgIPsPerCountry = totalIPs / countryIPCounts.size;
if (count > avgIPsPerCountry * 2) {
  // Triggers anomaly
}
```
**Example:** If average is 5 IPs per country, but one country has 12+ IPs → anomaly

#### **4. Time Pattern Analysis** ⏰
**What it does:** Detects traffic spikes (3x average hourly, 5x average minute)
**Code logic:**
```typescript
// Hourly: if count > (average × 3)
if (count > avgHourly * 3) { /* anomaly */ }

// Minute: if count > (average × 5)  
if (count > avgMinute * 5) { /* anomaly */ }
```
**Example:** Normal hour has 100 requests, but one hour has 350+ → anomaly

#### **5. Response Code Analysis** ⚠️
**What it does:** Flags 4xx errors above 10% threshold
**Code logic:**
```typescript
const percentage = count / totalRequests;
if (code.startsWith('4') && percentage > 0.1) {
  // Triggers anomaly (10% threshold)
}
```
**Example:** If 15% of requests return 404 errors → anomaly

#### **6. File Access Monitoring** 📁
**What it does:** Detects multiple accesses to suspicious file types
**Code logic:**
```typescript
const suspiciousExtensions = [
  'exe', 'dll', 'bat', 'cmd', 'ps1', 'vbs', 
  'js', 'jar', 'zip', 'rar'
];
if (pattern.count > 3) { /* anomaly */ }
```
**Example:** IP accesses 4+ .exe or .zip files → anomaly

#### **7. SSL/TLS Behavior** 🔒
**What it does:** Flags high SSL decryption rates and old TLS versions
**Code logic:**
```typescript
// Decryption rate: if > 80% of SSL traffic is decrypted
if (decryptionRate > 0.8) { /* anomaly */ }

// Old TLS: if > 5% uses old versions (SSLv2, SSLv3, TLSv1.0, TLSv1.1)
if (oldTLSRate > 0.05) { /* anomaly */ }
```
**Example:** 85% of SSL traffic is decrypted, or 10% uses TLSv1.0 → anomaly

#### **8. Bandwidth Usage** 📊
**What it does:** Flags IPs using 2x more bandwidth than average
**Code logic:**
```typescript
const avgBandwidthPerIP = totalBandwidth / ipBandwidthMap.size;
if (data.totalSize > avgBandwidthPerIP * 2) {
  // Triggers anomaly (2x threshold)
}
```
**Example:** Average IP uses 50MB, but one IP uses 120MB+ → anomaly

## Environment Variables

### Backend (.env)

```env
DATABASE_URL="postgresql://username:password@localhost:5432/tenex_logs"
JWT_SECRET="your-super-secret-jwt-key-change-in-production"
PORT=3001
FRONTEND_URL="http://localhost:3000"
```

## API Endpoints

### Authentication
- `POST /api/auth/register` - User registration
- `POST /api/auth/login` - User login

### Log Files
- `POST /api/logs/upload` - Upload log file
- `GET /api/logs/files` - Get user's log files
- `GET /api/logs/files/:id` - Get log file details and analysis
- `GET /api/logs/files/:id/entries` - Get paginated log entries

## Sample Log Files

### Comprehensive Test Log (`comprehensive_test_logs.csv`)
This file contains **66 log entries** designed to trigger **all 8 anomaly detection scenarios**:

1. **URL Pattern Analysis** - Same URL accessed 5 times in rapid succession
2. **User Agent Analysis** - 5 different suspicious scanning tools (sqlmap, nikto, nmap, metasploit, wget)
3. **Geographic Access** - 5 different IPs from the same country accessing malware sites
4. **Time Pattern Analysis** - 15 requests in 15 seconds at 10:00 AM (traffic spike)
5. **Response Code Analysis** - 10 consecutive 404 errors from same IP
6. **File Access Monitoring** - 5 suspicious file types (.exe, .bat, .dll, .zip, .ps1)
7. **SSL/TLS Behavior** - 6 requests to old TLS sites
8. **Bandwidth Usage** - 5 large video files (30MB each) from single IP

**To generate this file:**
```bash
cd data
python3 generate_comprehensive_test.py
```

### Other Test Files
- `sample_zscaler_logs.csv` - Basic ZScaler format logs
- `insider_threat_logs.csv` - Insider threat scenarios
- `iot_attack_logs.csv` - IoT device attacks
- `ransomware_logs.csv` - Ransomware attack patterns

### Manual Log Format
For testing, you can create a sample log file with this format:

```csv
2024-01-15 10:30:00,192.168.1.100,10.0.0.1,https://example.com,ALLOW,Mozilla/5.0,Technology,None,Low,None,GET,200,1024,2048,https://google.com,US,New York
2024-01-15 10:30:01,192.168.1.101,10.0.0.2,https://malicious-site.com,BLOCK,Mozilla/5.0,Malware,Malware.Generic,High,Malicious content,GET,403,0,0,https://google.com,Unknown,Unknown
```