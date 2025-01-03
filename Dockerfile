# Menggunakan base image untuk Golang
FROM golang:1.20

# Set working directory dalam container
WORKDIR /app

# Copy file go.mod dan go.sum terlebih dahulu
COPY go.mod go.sum ./

# Unduh dependensi sebelum copy source code
RUN go mod download

# Copy semua file proyek ke dalam container
COPY . .

# Build aplikasi
RUN go build -o main .

# Ekspos port 8080 (port default untuk aplikasi Anda)
EXPOSE 8080

# Perintah untuk menjalankan aplikasi
CMD ["./main"]
