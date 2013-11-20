#ifndef HW3_H
#define HW3_H

enum {
    AM_HW3 = 6,
    TIMER_PERIOD_MILLI = 250,	
    BASESTATION_ID = 0,
    GROUPID = 230
};

typedef nx_struct hw3_msg {
    nx_uint32_t time;
    nx_uint16_t nodeid;
    nx_uint16_t destid;
    nx_uint16_t groupid;
    nx_uint16_t counter;
    nx_uint16_t track[5];
    nx_uint8_t  count_index;
    nx_uint8_t  jump[5];
    
    
} hw3_msg;

enum {
QOS_NORMAL = 0,//node acts normal
QOS_DROP = 1,
QOS_DELAY = 2,
QOS_INJECT = 3
};


#endif /* HW3_H */
