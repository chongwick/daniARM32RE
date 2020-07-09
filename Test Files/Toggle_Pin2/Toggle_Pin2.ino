#define pinnum 2
#define pinmask (1<<25)
#define pinport PIOB
void setup() {
  pinMode(pinnum, OUTPUT);
  pinport -> PIO_SODR = pinmask;
  delay(1);
  pinport -> PIO_CODR = pinmask;
}

void loop() {
  // put your main code here, to run repeatedly:

}
