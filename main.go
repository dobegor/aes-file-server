package main

import (
	"flag"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"os/signal"
	"syscall"

	"github.com/gorilla/mux"
)

var (
	//crypting engine
	c Cryptos
)

func HomeHandler(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(200)
	fmt.Fprintf(w, "This is a simple encrypted file server.")
}

func FileHandler(w http.ResponseWriter, r *http.Request) {
	v := mux.Vars(r)

	f, err := os.Open("./data/" + v["file"])
	if err != nil {
		fmt.Println(err)
		ErrorHandler(w, r, 404, "Sorry, file not found")
		return
	}

	data, err := ioutil.ReadAll(f)
	if err != nil {
		fmt.Println(err)
		ErrorHandler(w, r, 500, "Reading file error: "+err.Error())
		return
	}

	data, err = c.Decrypt(data)
	if err != nil {
		fmt.Println(err)
		ErrorHandler(w, r, 500, "Error decrypting file: "+err.Error())
		return
	}

	w.WriteHeader(200)
	w.Write(data)
}

func ErrorHandler(w http.ResponseWriter, r *http.Request, code int, err string) {
	w.WriteHeader(code)
	fmt.Fprintf(w, "Error: %s", err)
}

func main() {
	httpAddr := flag.String("http.addr", ":8080", "HTTP address to listen on")
	keyFile := flag.String("key", "key.aes", "AES key file")
	flag.Parse()

	r := mux.NewRouter()
	r.StrictSlash(true)
	r.HandleFunc("/", HomeHandler)
	r.HandleFunc("/{file}", FileHandler)

	fmt.Println("Key file will be loaded from ", *keyFile)

	file, err := os.Open(*keyFile)
	if err != nil {
		fmt.Println("Loading key error: ", err)
		return
	}

	//32 bytes to fit AES256 key size
	key := make([]byte, 32)
	length, err := file.Read(key)

	if err != nil {
		fmt.Println("Loading key error: ", err)
		return
	}

	if length != 32 {
		fmt.Println("Wrong key size")
		return
	}

	c, err = NewAESCryptos(key)

	if err != nil {
		fmt.Println("Error initializing AES: ", err)
	}

	//channel to catch errors/SIGINT
	errors := make(chan error, 2)
	go func() {
		fmt.Println("The server is starting on ", *httpAddr)
		errors <- http.ListenAndServe(*httpAddr, r)
	}()

	go func() {
		c := make(chan os.Signal)
		signal.Notify(c, syscall.SIGINT)
		errors <- fmt.Errorf("%s", <-c)
	}()

	fmt.Println("Terminated: ", <-errors)
}
