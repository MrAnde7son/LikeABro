@load base/protocols/dns
@load base/frameworks/notice
@load base/frameworks/input

module Alexa;

export {
  redef enum Notice::Type += {
    Alexa::DNS_Not_In_Alexa_1M   
  };
  
  const alexa_file = "/opt/bro/share/bro/site/alexa/top-1m.txt" &redef;
  const ignore_dns: set[string] = { "-ms-", "ca-laptop" } &redef;
}

# Record for domains in file above
type Idx: record {
        domain: string;
};

# Table to store list of domains in file above
global alexa_table: set[string] = set();

# Pattern used to identify subdomains
const subdomains =  /^d?ns[0-9]*\./    |
                    /^smtp[0-9]*\./    |
                    /^mail[0-9]*\./    |
                    /^pop[0-9]*\./     |
                    /^imap[0-9]*\./    |
                    /^www[0-9]*\./     |
                    /^ftp[0-9]*\./     |
                    /^img[0-9]*\./     |
                    /^images?[0-9]*\./ |
                    /^search[0-9]*\./  |
                    /^nginx[0-9]*\./ &redef;

global he_answers: set[addr] &write_expire=5min;

function get_domain_2level(domain: string): string
    {
    local result = find_last(domain, /\.[^\.]+\.[^\.]+$/);
    if ( result == "" )
        return domain;
    return sub_bytes(result, 2, |result|);
    }

function get_domain_3level(domain: string): string
    {
    local result = find_last(domain, /\.[^\.]+\.[^\.]+\.[^\.]+$/);
    if ( result == "" )
        return domain;
    return sub_bytes(result, 2, |result|);
    }

event bro_init()
{
Input::add_table([$source=alexa_file,$mode=Input::REREAD,$name="alexa_table",$idx=Idx,$destination=alexa_table]);
}

event DNS::log_dns(rec: DNS::Info)
{
# Do not process the event if no query exists
if ( ! rec?$query ) return;

# If necessary, clean the query so that it can be found in the list of Alexa domains
local query = rec$query;
if ( subdomains in query )
  query = sub(rec$query,subdomains,"");
query = to_lower(query);
local domain_2 = get_domain_2level(query);
local domain_3 = get_domain_3level(query);

local not_ignore = T;
for (dns in ignore_dns)
{
  if(dns in query)
    not_ignore = F;
}

# Check if the query is not in the list of Alexa domains
if ( !(domain_2 in alexa_table) && !(domain_3 in alexa_table) && !(query in alexa_table) && not_ignore)
 {
  # Prepare the sub-message for the notice
  # Include the domain queried in the sub-message
  local sub_msg = fmt("%s",query);

  # Generate the notice
  # Includes the connection flow, host intiating the lookup, domain queried, and query answers (if available)
  NOTICE([$note=Alexa::DNS_Not_In_Alexa_1M,
          $msg=fmt("%s made a suspicious DNS lookup to unknown domain.", rec$id$orig_h),
          $sub=sub_msg,
          $id=rec$id,
          $uid=rec$uid,
          $identifier=cat(rec$id$orig_h,rec$query)]);
  }
}
