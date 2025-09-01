#!/usr/bin/env node

// Test script to debug the log parser
const fs = require('fs');

// Read the first line from correct_format_logs.csv
const content = fs.readFileSync('data/correct_format_logs.csv', 'utf-8');
const lines = content.split('\n').filter(line => line.trim());
const firstLine = lines[0];

console.log('=== TESTING LOG PARSER ===');
console.log('First line from correct_format_logs.csv:');
console.log(firstLine);
console.log('\nLine length:', firstLine.length);

// Simple CSV parsing to see what we get
const fields = [];
let current = '';
let inQuotes = false;

for (let i = 0; i < firstLine.length; i++) {
  const char = firstLine[i];
  
  if (char === '"') {
    inQuotes = !inQuotes;
  } else if (char === ',' && !inQuotes) {
    fields.push(current.trim());
    current = '';
  } else {
    current += char;
  }
}

fields.push(current.trim());

console.log('\n=== PARSED FIELDS ===');
console.log('Total fields:', fields.length);
console.log('Fields:');
fields.forEach((field, index) => {
  console.log(`  [${index}]: "${field}"`);
});

console.log('\n=== CRITICAL FIELDS ===');
console.log('Field [1] (login/company):', fields[1]);
console.log('Field [3] (url):', fields[3]);
console.log('Field [20] (department):', fields[20]);
console.log('Field [21] (clientIP):', fields[21]);
console.log('Field [22] (serverIP):', fields[22]);
console.log('Field [23] (requestMethod):', fields[23]);
console.log('Field [24] (responseCode):', fields[24]);
console.log('Field [25] (userAgent):', fields[25]);

console.log('\n=== VALIDATION ===');
console.log('Field count >= 20:', fields.length >= 20);
console.log('clientIP truthy:', !!fields[21]);
console.log('url truthy:', !!fields[3]);
console.log('Timestamp format check:', fields[0]);

// Test timestamp parsing
const timestamp = fields[0];
const date = new Date(timestamp);
console.log('Parsed timestamp:', date);
console.log('Timestamp valid:', !isNaN(date.getTime()));
