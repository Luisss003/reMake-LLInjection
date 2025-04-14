#include <stdio.h>
#include "cfg_processing.h"

struct config_data read_cfg(FILE * cfg_fp){
    char *line = NULL;
    size_t len = 0;
    struct config_data cfg_info;
    
  
    //Read first line (not really necessary since already have the pcap name);
    getline(&line, &len, cfg_fp);
    
    //Read victim IP
    getline(&line, &len, cfg_fp);
    line[strcspn(line, "\n")] = 0;
    inet_pton(AF_INET, line, &cfg_info.victim_ip);
  
    getline(&line, &len, cfg_fp);
    line[strcspn(line, "\n")] = 0;
    addr_aton(line, &cfg_info.victim_mac);
  
    getline(&line, &len, cfg_fp);
    line[strcspn(line, "\n")] = 0;
    cfg_info.victim_port = (uint16_t)atoi(line);
  
    //Read attacker IP
    getline(&line, &len, cfg_fp);
    line[strcspn(line, "\n")] = 0;
    inet_pton(AF_INET, line, &cfg_info.attacker_ip);
    
    //Read attacker MAC
    getline(&line, &len, cfg_fp);
    line[strcspn(line, "\n")] = 0;
    addr_aton(line, &cfg_info.attacker_mac);
  
    //Read attacker port
    getline(&line, &len, cfg_fp);
    line[strcspn(line, "\n")] = 0;
    cfg_info.attacker_port = (uint16_t)atoi(line);
  
    //Read replay victim IP
    getline(&line, &len, cfg_fp);
    line[strcspn(line, "\n")] = 0;
    inet_pton(AF_INET, line, &cfg_info.replay_victim_ip);
  
    //Read replay victim MAC
    getline(&line, &len, cfg_fp);
    line[strcspn(line, "\n")] = 0;
    addr_aton(line, &cfg_info.replay_victim_mac);
  
    //Read replay victim port
    getline(&line, &len, cfg_fp);
    line[strcspn(line, "\n")] = 0;
    cfg_info.replay_victim_port = (uint16_t)atoi(line);
  
    //Read replay attacker IP
    getline(&line, &len, cfg_fp);
    line[strcspn(line, "\n")] = 0;
    inet_pton(AF_INET, line, &cfg_info.replay_attacker_ip);
    //Read replay attacker MAC
    getline(&line, &len, cfg_fp);
    line[strcspn(line, "\n")] = 0;
    addr_aton(line, &cfg_info.replay_attacker_mac);
  
    //Read replay attacker port
    getline(&line, &len, cfg_fp);
    line[strcspn(line, "\n")] = 0;
    cfg_info.replay_attacker_port = (uint16_t)atoi(line);
  
    //Read interface
    getline(&line, &len, cfg_fp);
    line[strcspn(line, "\n")] = 0;
    cfg_info.interface = line;
  
    //Read timing
    getline(&line, &len, cfg_fp);
    line[strcspn(line, "\n")] = 0;
    cfg_info.timing = line;
    free(line);
    return cfg_info;
}