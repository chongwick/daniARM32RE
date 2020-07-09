volatile boolean l;

void interruptHandler() {
  pinMode(4, OUTPUT);
  digitalWrite(13, HIGH); 
}

void TC0_Handler()
{
    long dummy=REG_TC0_SR0; // vital - reading this clears some flag
                            // otherwise you get infinite interrupts
    l= !l;
}

//TC1 ch 0
void TC3_Handler()
{
        TC_GetStatus(TC1, 0);
        digitalWrite(13, l = !l);
}

void startTimer(Tc *tc, uint32_t channel, IRQn_Type irq, uint32_t frequency) {
        pmc_set_writeprotect(false);
        pmc_enable_periph_clk((uint32_t)irq);
        TC_Configure(tc, channel, TC_CMR_WAVE | TC_CMR_WAVSEL_UP_RC | TC_CMR_TCCLKS_TIMER_CLOCK4);
        uint32_t rc = VARIANT_MCK/128/frequency; //128 because we selected TIMER_CLOCK4 above
        TC_SetRA(tc, channel, rc/2); //50% high, 50% low
        TC_SetRC(tc, channel, rc);
        TC_Start(tc, channel);
        tc->TC_CHANNEL[channel].TC_IER=TC_IER_CPCS;
        tc->TC_CHANNEL[channel].TC_IDR=~TC_IER_CPCS;
        NVIC_EnableIRQ(irq);
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
  startTimer(TC1, 0, TC3_IRQn, 4); //TC1 channel 0, the IRQ for that channel and the desired frequency

  attachInterrupt(6, interruptHandler, CHANGE);
  interrupts();

}

void loop(){
      digitalWrite(13,l);
}
