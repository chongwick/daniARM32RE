void setup() {
  pinMode(13, OUTPUT);
  attachInterrupt(6, interruptHandler, CHANGE);
  interrupts();
}

void loop() {
  // put your main code here, to run repeatedly:

}

void interruptHandler() {
  pinMode(4, OUTPUT);
  digitalWrite(13, HIGH); 
}
