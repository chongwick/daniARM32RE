// Required libraries
#include <stdio.h>
#include <string.h>


// Globals
char buff[15];
int pass;

  
void setup() {
  // put your setup code here, to run once:
  pinMode(13, OUTPUT);
  
  pass = 0;
  
}

void loop() {
  // put your main code here, to run repeatedly:
 
  digitalWrite(13, HIGH);
  digitalWrite(13, LOW);
  digitalWrite(13, HIGH);
  digitalWrite(13, HIGH);
  digitalWrite(13, LOW);
  digitalWrite(13, HIGH);
  
  gets(buff);

  if(strcmp(buff,"password"))
  {
    printf("Wrong");
    exit(0);
    while(1){}
  }
  else
  {
    printf("Right");
    pass = 1;
  }

  if(pass)
  {
      digitalWrite(13, HIGH);
      digitalWrite(13, LOW);
      digitalWrite(13, HIGH);
      digitalWrite(13, HIGH);
      digitalWrite(13, LOW);
      digitalWrite(13, HIGH);
   }

}
