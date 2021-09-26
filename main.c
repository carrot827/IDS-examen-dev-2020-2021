#include "populate.h"
#include <stdlib.h>
#include <syslog.h>

void rule_matcher(Rule *rules_ds, ETHER_Frame *frame, int compteur)
{
    int afficherSourcePort;
    int afficherDestPort;
    char afficherIpSource[2048];
    char afficherIpDest[2048];

    for(int i = 0; i < compteur; i++)
    {
        bool protocol_match = false;

        if(frame->packet_ip.is_tcp && strcmp(rules_ds[i].protocol, "tcp") == 0)
        {
           protocol_match = true;
        }

        if(frame->packet_ip.is_udp && strcmp(rules_ds[i].protocol, "udp") == 0)
        {
           protocol_match = true;
           frame->packet_ip.is_ftp = false; 
        }

        if(strcmp(rules_ds[i].protocol, frame->packet_ip.data.protocole) == 0)
        {
            protocol_match = true;
        }

        if(protocol_match)
        {
           if(strcmp(rules_ds[i].adress_source, frame->packet_ip.source_ip) == 0 || strcmp(rules_ds[i].adress_source, "any") == 0)
           {
                if(strcmp(rules_ds[i].src_port, "") != 0)
                {
                    bool port_match = false;
                    if((frame->packet_ip.is_tcp && atoi(rules_ds[i].src_port) == frame->packet_ip.data.source_port) || strcmp(rules_ds[i].src_port, "any") == 0 )
                    {
                        port_match = true;
                    }
                    if((frame->packet_ip.is_udp && atoi(rules_ds[i].src_port) == frame->packet_ip.udp_data.source_port) || strcmp(rules_ds[i].src_port, "any") == 0) 
                    {
                        port_match = true;
                    }

                    if(port_match)
                    { 
                        if(strcmp(rules_ds[i].dest_adress, frame->packet_ip.destination_ip) == 0 || strcmp(rules_ds[i].dest_adress, "any") == 0)
                        {
                            if(strcmp(rules_ds[i].dest_port, "") != 0)
                            {
                                bool port_dest_match = false;
                                if((frame->packet_ip.is_tcp && atoi(rules_ds[i].dest_port) == frame->packet_ip.data.destination_port)|| strcmp(rules_ds[i].dest_port, "any") == 0) 
                                {
                                    port_dest_match = true;
                                }
                                if((frame->packet_ip.is_udp && atoi(rules_ds[i].dest_port) == frame->packet_ip.udp_data.destination_port)|| strcmp(rules_ds[i].dest_port, "any") == 0) 
                                {
                                    port_dest_match = true;
                                }

                                if(port_dest_match)
                                {
                                    if((frame->packet_ip.is_tcp && strstr((const char*)frame->packet_ip.data.data, rules_ds[i].content) != NULL) || (frame->packet_ip.is_udp && strstr((const char*)frame->packet_ip.udp_data.data, rules_ds[i].content) != NULL))
                                    {
                                                                                       
                                        printf("\n--------------------------------- | ALERT ! | ---------------------------------\n\n\a");
                                        printf("La règle %d correspond ! \n", i+1);
                                        printf("Message: %s\n", rules_ds[i].msg);
                                        if(strcmp(rules_ds[i].content, "") != 0)
                                        {
                                            printf("Contenu: %s\n", rules_ds[i].content);
                                        }
                                        printf("Le protocol utilisé est: %s\n", rules_ds[i].protocol);
                                        printf("L'adress source est: %s le port source est: ", frame->packet_ip.source_ip);
                                        strcpy(afficherIpSource, frame->packet_ip.source_ip);
                                        if(frame->packet_ip.is_udp)
                                        {
                                            printf("%d (UDP)\n", frame->packet_ip.udp_data.source_port);
                                            afficherSourcePort = frame->packet_ip.udp_data.source_port;
                                        }

                                        if(frame->packet_ip.is_tcp)
                                        {
                                            printf("%d (TCP)\n", frame->packet_ip.data.source_port);
                                            afficherSourcePort = frame->packet_ip.data.source_port;
                                        }

                                        printf("L'adresse de destination est: %s le port de destination est: ", frame->packet_ip.destination_ip);
                                        strcpy(afficherIpDest, frame->packet_ip.destination_ip);
                                        if(frame->packet_ip.is_udp)
                                        {
                                            printf("%d (UDP)\n", frame->packet_ip.udp_data.destination_port);
                                            afficherDestPort = frame->packet_ip.udp_data.destination_port;
                                        }

                                        if(frame->packet_ip.is_tcp)
                                        {
                                            printf("%d (TCP)\n", frame->packet_ip.data.destination_port);
                                            afficherDestPort = frame->packet_ip.data.destination_port;
                                        }

                                        openlog("Intrusion detectée par l'IDS", LOG_ALERT | LOG_CONS,LOG_USER);
                                        syslog(LOG_ALERT,"Message: %s | Contenu: %s | Protocol %s | Adresse source: %s | Port source: %d || Adresse destination: %s | Port destination: %d", rules_ds[i].msg, rules_ds[i].content, rules_ds[i].protocol,afficherIpSource, afficherSourcePort, afficherIpDest, afficherDestPort);
                                        closelog();
                                        printf("\nCet évenement a été repporté dans syslog! --> /var/log/syslog\n");


                                        printf("\n-------------------------------------------------------------------------------\n");
                                    }                    
                                }
                            } 
                        }
                    }
                }
            }
        }
    }  

}


int count_line(char * nomfichier)
{
    int nb_ligne = 0;
    char ligne[MAXLINE];
    FILE *file = fopen(nomfichier, "r");
    if(file==NULL)
    {
        printf("\nError 404 file not found\n");
        exit(0);
    }
    while(fgets(ligne, MAXLINE, file) != NULL)
    {
        nb_ligne ++;
    }
    fclose(file);
    return nb_ligne;
}


void read_rules(FILE * file, Rule **rules_ds, int count) 
{
    printf("Lecture du fichier de règles en cours ...\n");
    *rules_ds = (Rule*) malloc(count*(sizeof(Rule))); 

    if(file==NULL)
    {
        printf("\nError 404 file not found\n");
        exit(0);
    }

    char ligne[MAXLINE];
    int j = 0;
    while(fgets(ligne, MAXLINE, file) != NULL)
    {
		char *token = NULL;
        for(int i =0; i < 7; i++)
        {
			if(i==0) 
			{
                 token = strtok(ligne, " ");
			}else
            {
				token = strtok(NULL, " ");
			}

            switch(i)
            {
		        case 0 :
		                strcpy((*rules_ds)[j].type_alert, token);
		                break;
		        case 1 :
		                strcpy((*rules_ds)[j].protocol, token);
	                    break;
		        case 2 :
		                strcpy((*rules_ds)[j].adress_source, token);
		                break;
                case 3 :
                        strcpy((*rules_ds)[j].src_port, token);
                        break;
                case 4 :
                        strcpy((*rules_ds)[j].destination, token);
                        break;
                case 5 :
                        strcpy((*rules_ds)[j].dest_adress, token);
                        break;
                case 6 :
                        strcpy((*rules_ds)[j].dest_port, token);
                        break;
                default :
                        printf("Unknow error");
            }
        }
		
		for(int i = 0; i < 4; i++)
		{
			token = strtok(NULL, "\"");
			if(i == 1)
			{
				strcpy((*rules_ds)[j].msg, token);
			}
			if(i == 3)
			{
                if(token != NULL)
                {
				    strcpy((*rules_ds)[j].content, token);
			    }
                else
                {
                    strcpy((*rules_ds)[j].content, "");
                }
			}
		}
        j++;
        }



       

printf("Lecture du fichier de règles terminée.\n");
}



void my_packet_handler(u_char *args,const struct pcap_pkthdr *header,const u_char *packet)
{       
    ETHER_Frame superframe; 
    populate_packet_ds(header, packet, &superframe); 
    u_char **array =  (u_char**) args;
    Rule *r = (Rule *) array[0];
    int compteur = (int) *array[1];

    if(superframe.ethernet_type == IPV4)
    { 
        rule_matcher(r, &superframe, compteur);
    }        
}

void print_help(char *argc)
{
    system("clear");
    printf("\n\n\n- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -\n");
    printf("____________");
    printf("\n| %s OPTION |\n", argc);
    printf("------------\n");
    printf("\n Bienvenue dans l'IDS realisé par Frédéric Grandgagnage & Jérémy Hugé\n");
    printf("\n- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -\n\n\n\n");
    printf("Afin d'utiliser cet IDS correctement, veuillez placer en option le nom de votre fichier de règles.\n\n");
    printf("""Par exemple: \t\"./ids ids.rules\"\n\n\n\n""");

    exit(EXIT_SUCCESS);
}



int main(int argc, char *argv[]) 
{
    if(argc < 2 || argc >2)
    {
        printf("""Erreur, utilisez l'option \"-h\" pour afficher l'aide\n\a""");
        exit(EXIT_FAILURE);
    }
    else if (strcmp(argv[1], "-h") == 0)
    {
        print_help(argv[1]);
    }

    char *device = "eth0";
    char *fichier = argv[1];

    printf("Device: %s\n", device);

    char error_buffer[PCAP_ERRBUF_SIZE];
    pcap_t *handle;

    handle = pcap_create(device,error_buffer);
    pcap_set_timeout(handle,10);
    pcap_activate(handle);
    int total_packet_count = 0;
    int compteur = 0;
    compteur = count_line(fichier);

    Rule *r = NULL; 
    FILE *file = fopen(fichier, "r");        
    if(file==NULL)
    {
        printf("\nError 404 file not found\n");
        exit(0);
    }

        
    read_rules(file, &r, compteur);
        
    fclose(file);
    u_char* array[2];
    array[0] = (u_char*) r;
    array[1] = (u_char*) &compteur;

    pcap_loop(handle, total_packet_count, my_packet_handler, (u_char*)array);

    free(r); 
    return 0;
}
