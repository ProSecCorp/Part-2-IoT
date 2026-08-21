/*
 * \file
 *    The BLACKHOLE node code.
 * \author Emanuele Artusi <artusi.emanuele.03@gmail.com>
 */

#include "contiki.h"
#include "net/routing/routing.h"

#include "sys/log.h"

#define LOG_MODULE "BLACKHOLE"
#define LOG_LEVEL LOG_LEVEL_DBG


PROCESS(blackhole_process, "Blackhole node");
AUTOSTART_PROCESSES(&blackhole_process);


/*---------------------------------------------------------------------------*/
PROCESS_THREAD(blackhole_process, ev, data)
{
  PROCESS_BEGIN();

  LOG_INFO("Blackhole started\n");


  /* entra nella rete RPL */
  NETSTACK_ROUTING.init();


  while(1) {

    PROCESS_WAIT_EVENT();

  }


  PROCESS_END();
}