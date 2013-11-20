/*
*
*
*/

#include <Timer.h>
#include "HW3.h"
#include "AM.h"
#include <stdio.h>

//this function returns the ID of parent. It uses a predefined static routing table
uint8_t GetMyParent(uint8_t nodeid)
{
    uint8_t parent = -1;

    switch (nodeid)
    {
       case 1:
       case 2:
       case 9:
       case 10:
       case 12:
            parent = 0;
            break;
       case 3:
       case 4:
            parent = 1;
            break;
       case 5:
       case 6:
            parent = 2;
            break;
       case 7:
            parent = 4;
            break;
       case 8:
            parent = 6;
	    break;
       case 23:
       case 24:
       case 25:
            parent = 9;
            break;
       case 21:
            parent = 10;
            break;
       case 11:
       case 14:
       case 13:
            parent = 12;
            break;
       case 26:
            parent = 25;
            break;
       case 22:
       case 20:
            parent = 21;
            break;
       case 19:
            parent = 11;
            break;
       case 18:
       case 15:
            parent = 14;
            break;
       case 16:
            parent = 15;
            break;
       case 17:
            parent = 13;
            break;
       default:
            parent = 0;
            break;                           
    }
    return parent;
}
//Determine whether I am going to do QoS Attack or not! 
int QOS_Attack(int myID)
{
    char buf[20];
    int array[2];
    FILE *fp; 
    int qos_attack = 0;

    dbg("FILE", "Inside ReadMaliciousIDs function\n");
    fp = fopen("malicious_list.txt", "r");
    dbg("FILE", "After fopen\n");
    if (fp == NULL)
    {
        dbg_clear("ERR", "\n");
        dbg("ERR", "can not open malicious_list.txt file for read\n\n");
        exit(-2);
    }
    while ( fgets(buf, sizeof(buf), fp) != NULL)
    {
        sscanf(buf, "%d %d", &array[0], &array[1]);
        dbg("FILE", "%d %d\n", array[0], array[1]);
        if (array[0] == myID)
        {
            qos_attack = array[1];
            switch (qos_attack)
            {
                case 1:
                    dbg("BOOT", "QOS_ATTACK: DROP\n");
                    break;
                 case 2:
                    dbg("BOOT", "QOS_ATTACK: DELAY\n");
                    break;
                 case 3:
                    dbg("BOOT", "QOS_ATTACK: INJECT\n");
                    break;
            }
            break;
        }
    }
    fclose(fp);
    dbg("FILE", "Exiting Read file function\n");
    return qos_attack;
}


module HW3C {
    uses interface Boot;
    uses interface Leds;
    uses interface Timer<TMilli> as Timer0;
    uses interface LocalTime<TMilli>;
    uses interface SplitControl as RadioControl;
    uses interface Packet as RadioPacket;       //to create a packet
    uses interface AMPacket as RadioAMPacket;   //To extract information out of packets
    uses interface AMSend as RadioSend;
    uses interface Receive as RadioReceive;
}

implementation {
    uint16_t counter = 0;
    bool busy = FALSE;
    message_t pkt;

    uint64_t num_messages = 0;
    uint64_t total_delay = 0;
    uint64_t delay;  
    uint8_t my_parent;
    uint8_t qos_attack;
    
    /*to handle message buffer */
    enum {    
    RADIO_QUEUE_LEN = 12,
  };
  
  message_t  radioQueueBufs[RADIO_QUEUE_LEN];
  message_t  * ONE_NOK radioQueue[RADIO_QUEUE_LEN];
  uint8_t    radioIn, radioOut;
  bool       radioBusy, radioFull;

//****************************************************************************
//Prototypes
//****************************************************************************
task void RadioSendTask();

//****************************************************************************
//internal functions
//****************************************************************************

 void DropBlink(char * str) {
    call Leds.led2Toggle();
    dbg("LED", "DropBlink: %s \n", str);
  }
 
  void FailBlink() {
    call Leds.led1Toggle();
    dbg("LED", "FailBlink\n");
  }
 void SendBlink(am_addr_t dest) {
    call Leds.led0Toggle();
    dbg("LED", "SendBlink to: %u\n",dest);
  }

message_t* QueueIt(message_t *msg, void *payload, uint8_t len) 
{
    message_t *ret = msg;

    atomic 
    {
      if (!radioFull)
	  {
    	  ret = radioQueue[radioIn];
	      radioQueue[radioIn] = msg;

    	  radioIn = (radioIn + 1) % RADIO_QUEUE_LEN;
	
	      if (radioIn == radioOut)
	        radioFull = TRUE;

    	  if (!radioBusy)
	        {
	          post RadioSendTask();
    	      radioBusy = TRUE;
	        }
	 }
     else
	    DropBlink("From Queue Function");
    }
    
    return ret;
}
 
//************************************************************************************ 
//Events
//************************************************************************************ 

//********** 
//Booted
//********* 

    event void Boot.booted() {

        uint8_t i;  //index to initialize queues

        dbg ("BOOT", "Application booted (%d).\n", TOS_NODE_ID);

        qos_attack = QOS_Attack(TOS_NODE_ID); 
        
        if (TOS_NODE_ID == BASESTATION_ID)
        {       
            num_messages = 0;
            total_delay = 0;
        }
        
        my_parent = GetMyParent (TOS_NODE_ID); 

        dbg("DBG", "I will forward received packets to Node_%d\n",my_parent);
            
	for (i = 0; i < RADIO_QUEUE_LEN; i++)
	    radioQueue[i] = &radioQueueBufs[i];
      radioIn = radioOut = 0;
      radioBusy = FALSE;
      radioFull = TRUE;

      call RadioControl.start();
        
    }
//********** 
//Radio Start Done
//********* 

    event void RadioControl.startDone(error_t err)
    {
        if (err == SUCCESS) 
        {
            dbg ("DBG", "Radio Started.\n");
            radioFull = FALSE;
            dbg ("SETUP", "Starting the timer\n");
            //call Timer0.startPeriodic(TIMER_PERIOD_MILLI);
	    call Timer0.startOneShot(TIMER_PERIOD_MILLI);
        }
        else 
        { 
            call RadioControl.start();
        }
    }
//********** 
//Radio Stop Done
//********* 

    event void RadioControl.stopDone(error_t err)
    {}
//********** 
//Time Fired
//********* 

    event void Timer0.fired() {
        message_t* msg;
        hw3_msg * btrpkt;
        counter ++;
        //call Leds.set(counter);

        if (TOS_NODE_ID != BASESTATION_ID)
        {
            atomic 
            if (!radioFull)
            {
                msg = radioQueue[radioIn];
                btrpkt = (hw3_msg*) (call RadioPacket.getPayload(msg, sizeof (hw3_msg)));
                if (btrpkt == NULL)
                {
                    dbg ("ERR", "payload is smaller than length!\n");
                    exit(-1);
                }
                btrpkt->nodeid = TOS_NODE_ID;
                btrpkt->counter = counter;
                btrpkt->destid = my_parent;
                btrpkt->time = call LocalTime.get();
		btrpkt->count_index=0;
		btrpkt->track[btrpkt->count_index]=TOS_NODE_ID;
		btrpkt->jump[btrpkt->count_index]= call LocalTime.get();
		//btrpkt->pretime=call LocalTime.get();
                //Set packet header data. These info will be adjusted in each hop
                call RadioPacket.setPayloadLength(msg, sizeof (hw3_msg));
                call RadioAMPacket.setDestination(msg, my_parent);
                call RadioAMPacket.setSource(msg, TOS_NODE_ID);
                dbg("PKG", "Generated Packet. source: %d, destination: %d, timestamp: %d\n", btrpkt->nodeid, btrpkt->destid, btrpkt->time);

                 ++radioIn;
                 if(radioIn >=RADIO_QUEUE_LEN)
                     radioIn=0;
                 if(radioIn == radioOut)
                    radioFull = TRUE;
                 if (!radioBusy)
                 {
                     post RadioSendTask();
                     radioBusy = TRUE;
                 }
            }
            else
            {
                DropBlink("Timer Fired Function");
            }
        }
        else
        {
            //Funny ha!!! Look at the printed values for total_delay, first one is always zero!!!! this is a bug! 
            //dbg("BASE", "Num_messages = %d, total_delay = %d, total_delay = %d\n", num_messages, total_delay, total_delay);
            //dbg("BASE", "Num_messages = %d, Avg_Delivery_Delay = %.2f\n", num_messages, (float)total_delay/(float)num_messages);
            dbg_clear("BASE","\n");
            dbg("BASE", "=========Base Station Statistics============\n");
            dbg("BASE", "Total Received Packages:%d\n", num_messages);
            dbg("BASE", "Avgerage Delivery Delay:%.2f\n", (float)total_delay/(float)num_messages);
	    dbg("BASE", "Avgerage Throughput:%.2f\n", (((float)total_delay*28)/((float)num_messages/1000)));
            dbg("BASE", "============================================\n\n");
        }
    }
//********** 
//Radio Receive
//********* 
    event message_t* RadioReceive.receive(message_t* msg, void* payload, uint8_t len)
    {
	uint32_t localTime;
	int i ,j,k,l,m,n,o;
	int route[5];
	int check=0;
	int dropper[5];
	int c=0;
	int delayer[5];
	int route1[5];
	int check1=0;
	int b=0;
	int a=0;
	int injecter[5];
	int route2[5];
	int check2=0;
	int value=0;
	int delay_rec[27][3];
	int total_path_delay=0;
	
	message_t* msg1;
 	hw3_msg * btrpkt1;
	
	for(i=0;i<5;i++)
	  
	{
	  route[i]=0;
	  route1[i]=0;
	  route2[i]=0;
	  dropper[i]=0;
	  delayer[i]=0;
	  injecter[i]=0;
	}
	for(i=1;i<27;i++)
	  
	{ for (j=1;j<=2;j++)
	  {
	    delay_rec[i][j]=0;
	    //printf()
	  }
	  }
       
        
    	
	if (len == sizeof(hw3_msg))
    	{
        	hw3_msg* btrpkt = (hw3_msg*)payload;
            am_addr_t dest = call RadioAMPacket.destination(msg);

            dbg("DBG", "Received a packet. Origin:%d, counter:%d, next hop:%d, timestamp:%d:\n", btrpkt->nodeid, btrpkt->counter, btrpkt->destid, btrpkt->time);

            if (TOS_NODE_ID ==  dest) 
            {
                if (TOS_NODE_ID == BASESTATION_ID) 
                {
                    num_messages++;
                    localTime = call LocalTime.get();
		    delay = localTime - btrpkt->time;
                    total_delay += delay;
		     btrpkt->jump[0]=0;
                   
		    btrpkt->count_index=btrpkt->count_index+1;
		    btrpkt->track[btrpkt->count_index]=TOS_NODE_ID;
		    
		     for(i=0;i<(btrpkt->count_index);i++)
			{
			  value=value+btrpkt->jump[i];
			  //printf("value%d\n",value);
			}
			btrpkt->jump[btrpkt->count_index]= call LocalTime.get()-value;
			for(i=0;i<=(btrpkt->count_index);i++)
			{
			  total_path_delay=total_path_delay+(btrpkt->jump[i]);
			  //printf("value%d\n",value);
			}
			if(delay_rec[btrpkt->nodeid][2]!=1)
			{
			  delay_rec[btrpkt->nodeid][1]=total_path_delay;
			  printf("%d\n",delay_rec[btrpkt->nodeid][1]);
			  delay_rec[btrpkt->nodeid][2]=1;
			  printf("%d\n",delay_rec[btrpkt->nodeid][2]);
			}
			if(btrpkt->nodeid==26)
			{printf("the delays are follows");
			  for(k=1;i<=27;i++)
	  
			  { 
			      printf("\nnumber%d:",   delay_rec[k][1],   delay_rec[k][2]);
			  
			   
			    }
			  
			  
			}
		      
		 







		  dbg("BASE","\nRoute is :\n");
			    for(i=0;i<5;i++)
			    {
			      printf("%d\t", btrpkt->track[i]);
			    }
	        dbg("BASE","\nHop Delays are :\n");
		            
			    for(i=0;i<5;i++)
			    {
			      printf("%d\t", btrpkt->jump[i]);
			    }
		    
		    
		 
                    dbg("DBG", "Received a packet. LocalTime: %d, Timestamp of packet: %d, delay:%d\n", localTime, btrpkt->time, delay);
                    dbg("DBG", "BS received a packet, statistics==> num_messages: %d, total_delay:%d, total_delay: %d\n",num_messages, total_delay, total_delay);
                }
                else
                 {
			  //Insert it into buffer to be relayed forward
			  dbg("FWD", "QUEUE it to be relayed to 400 %d\n",my_parent);
			  //Adjust source and destination of the packet for next hop
			// call RadioAMPacket.setDestination(msg, my_parent);
			  //call RadioAMPacket.setSource(msg, TOS_NODE_ID);
			  //myTime=call LocalTime.get();
			////  printf("I am intermediate station%d\n",myTime);
				//    printf("My node id(EVENT5) %d\n",TOS_NODE_ID);  
			  switch (qos_attack)
			  {
			     
				case 1:
				  call RadioAMPacket.setDestination(msg, my_parent);
				  call RadioAMPacket.setSource(msg, TOS_NODE_ID);
				  
				  btrpkt->nodeid = TOS_NODE_ID;
				  btrpkt->counter = 0;
				  btrpkt->destid = my_parent;
				  btrpkt->time = 0;
				  btrpkt->count_index=btrpkt->count_index+1;
				  btrpkt->track[btrpkt->count_index]=TOS_NODE_ID+100;
				  for(i=0;i<(btrpkt->count_index);i++)
				  {
				    value=value+btrpkt->jump[i];
				    
				  }
				  btrpkt->jump[btrpkt->count_index]= call LocalTime.get()-value;
				  //btrpkt->pretime=call LocalTime.get();
				 // btrpkt->duty = btrpkt->duty+2; // add the duty cycle
				  //btrpkt->delay[btrpkt->count_index]=0;
				  msg=QueueIt(msg, NULL, len);
				  //dbg("BOOT", "packetdropped%d\n",btrpkt->counter);
				  printf("Dropping");
				 // dbg("PKG", "Generated Packet. source: %d, destination: %d, timestamp: %d\n", btrpkt->nodeid, btrpkt->destid, btrpkt->time);
			      
				break;
			     
				case 2:
				  call RadioAMPacket.setDestination(msg, my_parent);
				  call RadioAMPacket.setSource(msg, TOS_NODE_ID);
				  btrpkt->count_index=btrpkt->count_index+1;
				  btrpkt->track[btrpkt->count_index]=TOS_NODE_ID+200;
				 // btrpkt->duty = btrpkt->duty+2;
				  //btrpkt->delay[btrpkt->count_index]=TOS_NODE_ID;
				  printf("delaying");
				  for(i=0;i<(btrpkt->count_index);i++)
				  {
				    value=value+btrpkt->jump[i];
				    
				  }
				  btrpkt->jump[btrpkt->count_index]= call LocalTime.get()-value+125;
				 
				  
				  // btrpkt->pretime=call LocalTime.get();
				  //localTime= localTime+125;
				  msg=QueueIt(msg,  payload, len);
				 //dbg("PKG", "Generated Packet. source: %d, destination: %d, timestamp: %d\n", btrpkt->nodeid, btrpkt->destid, btrpkt->time);
				  break;
			      
				case 3:
				    call RadioAMPacket.setDestination(msg, my_parent);
				    call RadioAMPacket.setSource(msg, TOS_NODE_ID);
				    btrpkt->count_index=btrpkt->count_index+1;
				    btrpkt->track[btrpkt->count_index]=TOS_NODE_ID+300;
				    for(i=0;i<(btrpkt->count_index);i++)
				  {
				    value=value+btrpkt->jump[i];
				    
				  }
				  btrpkt->jump[btrpkt->count_index]= call LocalTime.get()-value;
				   // btrpkt->pretime=call LocalTime.get();
				    msg=QueueIt(msg, payload, len);
				  
				    
				    atomic 
				if (!radioFull)
				{
				    btrpkt1 = (hw3_msg*) (call RadioPacket.getPayload(msg, sizeof (hw3_msg)));
				    if (btrpkt1 == NULL)
				    {
					dbg ("ERR", "payload is smaller than length!\n");
					exit(-1);
				    }
				    btrpkt1->groupid = btrpkt->groupid;
				    btrpkt1->time = btrpkt->time;
				    btrpkt1->nodeid = btrpkt->nodeid;
				    btrpkt1->counter = btrpkt->counter;
				    btrpkt1->destid = btrpkt->destid;
				    //btrpkt1->num_hops = btrpkt->num_hops;
				    /*for (i = 0; i < 5; i++) 
				    {
					btrpkt1->track[i] = btrpkt->track[i]; 
				    }*/
				    call RadioPacket.setPayloadLength(msg, sizeof (hw3_msg));
				    call RadioAMPacket.setDestination(msg, my_parent);
				    call RadioAMPacket.setSource(msg, TOS_NODE_ID);

				    msg1 = radioQueue[radioIn];
				    radioQueue[radioIn] = msg;
				    msg = msg1;

				    radioIn = (radioIn + 1) % RADIO_QUEUE_LEN;
				    if(radioIn >=RADIO_QUEUE_LEN)
					radioIn=0;
				    if(radioIn == radioOut)
					radioFull = TRUE;
				    if (!radioBusy)
				    {
					post RadioSendTask();
					radioBusy = TRUE;
				    }
			    }
				    
				  //  printf("injecting");
				    //dbg("PKG", "Generated Packet. source: %d, destination: %d, timestamp: %d\n", btrpkt->nodeid, btrpkt->destid, btrpkt->time);
				  break;
			      
				  default:
				  call RadioAMPacket.setDestination(msg, my_parent);
				  call RadioAMPacket.setSource(msg, TOS_NODE_ID);
				  btrpkt->count_index=btrpkt->count_index+1;
				  btrpkt->track[btrpkt->count_index]=TOS_NODE_ID;
				  for(i=0;i<(btrpkt->count_index);i++)
				  {
				    value=value+btrpkt->jump[i];
				    
				  }
				  btrpkt->jump[btrpkt->count_index]= call LocalTime.get()-value;
				  //btrpkt->pretime=call LocalTime.get();
				  //btrpkt->delay[btrpkt->count_index]=0;
				  //btrpkt->delay[btrpkt->count_index]=call LocalTime.get();
				 // btrpkt->duty = btrpkt->duty+2;
				  msg=QueueIt(msg, payload, len);
				//  dbg("PKG", "Generated Packet. source: %d, destination: %d, timestamp: %d\n", btrpkt->nodeid, btrpkt->destid, btrpkt->time);
				break;
			  }
				      
		

		      }
            }
            else   //not destined for me, drop it!
            {
                dbg("DROP", "Droped the packet__%d, %d, %d\n", btrpkt->nodeid, btrpkt->destid, btrpkt->time);
            }  
            
    	}
        else
        {
            dbg("DROP", "wrong lenght! %d instead of %d\n", len, sizeof(hw3_msg));
        }
    	return msg;
    }  
//********** 
//Send Done
//********* 
   
  event void RadioSend.sendDone(message_t* msg, error_t error) {
    if (error != SUCCESS)
      FailBlink();
    else
      atomic
	if (msg == radioQueue[radioOut])
	  {
	    if (++radioOut >= RADIO_QUEUE_LEN)
	      radioOut = 0;
	    if (radioFull)
	      radioFull = FALSE;
	  }
    
    post RadioSendTask();
  }
  
 //*********************************************************************
 //Tasks
 //******************************************************************** 
    task void RadioSendTask() {
    uint8_t len;
    am_addr_t addr;
    message_t* msg;
    hw3_msg *btrpkt;
    
    atomic
      if (radioIn == radioOut && !radioFull)
	{
	  radioBusy = FALSE;
	  return;
	}

    msg = radioQueue[radioOut];

    btrpkt = (hw3_msg*) (call RadioPacket.getPayload(radioQueue[radioOut], sizeof (hw3_msg)));
    dbg ("DBG", "nodeid:%d, parent:%d, counter:%d\n",btrpkt->nodeid, btrpkt->destid, btrpkt->counter);
    len = call RadioPacket.payloadLength(msg);
    addr = call RadioAMPacket.destination(msg);

    dbg("DBG", "len:%d, addr:%d\n",len,addr);
    
    if (call RadioSend.send(addr, msg, len) == SUCCESS)
    {
        SendBlink(addr);
    }
    else
    {
	    FailBlink();
      	post RadioSendTask();
    }
  }

 
  
}
