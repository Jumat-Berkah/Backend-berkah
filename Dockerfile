# Menggunakan base image untuk Golang
FROM golang:1.20

# Set working directory dalam container
WORKDIR /app

# Copy semua file dari direktori lokal ke dalam container
COPY . .

# Mengunduh dependensi Go
RUN go mod tidy

# Build aplikasi
RUN go build -o main .

# Ekspos port 8080 (port default untuk aplikasi Anda)
EXPOSE 8080

# Perintah untuk menjalankan aplikasi
CMD ["./main"]
