volatile boolean l;

void TC0_Handler()
{
    long dummy=REG_TC0_SR0; // vital - reading this clears some flag
                            // otherwise you get infinite interrupts
    l= !l;
}

void setup(){
  pinMode(13,OUTPUT);
  pinMode(2,OUTPUT);    // port B pin 25  
  analogWrite(2,255);   // sets up some other registers I haven't worked out yet
  REG_PIOB_PDR = 1<<25; // disable PIO, enable peripheral
  REG_PIOB_ABSR= 1<<25; // select peripheral B
  REG_TC0_WPMR=0x54494D00; // enable write to registers
  REG_TC0_CMR0=0b00000000000010011100010000000000; // set channel mode register (see datasheet)
  REG_TC0_RC0=100000000; // counter period
  REG_TC0_RA0=30000000;  // PWM value
  REG_TC0_CCR0=0b101;    // start counter
  REG_TC0_IER0=0b00010000; // enable interrupt on counter=rc
  REG_TC0_IDR0=0b11101111; // disable other interrupts

  NVIC_EnableIRQ(TC0_IRQn); // enable TC0 interrupts

}

void loop(){
      digitalWrite(13,l);
}
