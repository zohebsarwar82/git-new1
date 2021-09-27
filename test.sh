#!/bin/bash
#########
# Setup script installing Twistlock Defender deployment
# Global flags
debug_log_level="false"
working_folder="$(pwd)/.twistlock"
install_log="${working_folder}/twistlock-install.log"

defender_type_docker=defender
defender_type_linux_server=defender-server
defender_type_tas=defender-tas

# Silence tput errors when script is run by process not attached to a terminal
tput_silent() {
	tput "$@" 2>/dev/null
}

exit_on_failure() {
	last_command=$_
	rc=$1
	message=$2
	ignore_logs=$3
	if [[ ${rc} != 0 ]]; then
		if [[ "${ignore_logs}" != "true" ]]; then
			# Print the last lines of the install log
			logs=$(tail --lines=2 ${install_log})
			print_error "${message} - ${logs}"
		else
			print_error "${message}"
		fi
		popd > /dev/null
		exit ${rc}
	fi
}

# stop the program and exit with the given message
exit_now() {
	local message=$1
	print_error "${message}"
	exit 1
}

print_info() {
  info=$1
  echo "$(tput_silent setaf 2)${info}.$(tput_silent sgr0)"
  echo ${info} >> ${install_log}
}

print_debug() {
  debug=$1
  if [[ ${debug_log_level} == "true" ]]; then
	echo "$(tput_silent setaf 7)${debug}.$(tput_silent sgr0)"
  fi
  echo ${debug} >> ${install_log}
}

print_error() {
  error=$1
  echo "$(tput_silent setaf 1)${error}.$(tput_silent sgr0)"
  echo ${error} >> ${install_log}
}

print_warning() {
  warning=$1
  echo "$(tput_silent setaf 3)${warning}.$(tput_silent sgr0)"
  echo ${warning} >> ${install_log}
}

show_help() {
	echo \
'
Usage: defender.sh [API_ADDRESS] [HEADER] [CONSOLE_CN].

Installs Twistlock Defender.

Parameters:
  [API_ADDRESS]    The API server address
  [HEADER]         Authentication header
  [CONSOLE_CN]     Address for the Twistlock Console
'
}

# Get all local ips of the current host
get_local_ip() {
	ip=""
	# In some distributions, grep is not compiled with -P support.
	# grep: support for the -P option is not compiled into this --disable-perl-regexp binary
	# For those cases, use pcregrep
	if command_exists pcregrep; then
		ip=$(ip -f inet addr show | pcregrep -o 'inet \K[\d.]+')
	else
		ip=$(ip -f inet addr show | grep -Po 'inet \K[\d.]+')
	fi
	ip_result="IP:"
	ip_result+=$(echo ${ip} | sed 's/ /,IP:/g')
	echo ${ip_result}
}

command_exists() {
	command -v "$@" > /dev/null 2>&1
}

download_certs() {
	local ip=${san:-$(get_local_ip)}
	print_debug "IPs: ${ips}"
	local hostname=$(hostname --fqdn 2>/dev/null)
	if [[ $? == 1 ]]; then
		# Fallback to hostname without domain
		hostname=$(hostname)
	fi

	if [[ ${hostname} == *" "* ]]
	then
	  hostname=$(hostname)
	  print_debug "FQDN contains space. Using '${hostname}'."
	fi

	print_info "Generating certs for ${hostname} ${ip}"

	${curl} --header "${authorization_header}" "${api_addr}/certs/server-certs.sh?hostname=${hostname}&ip=${ip}" -o certs.sh > ${install_log} 2>&1
	exit_on_failure $? "Failed to download certificates"
	bash certs.sh
	exit_on_failure $? "Failed to generate certificates"
}

# On default, skip TLS parameters in defender installation
skip_tls_flag=" -k "
additional_defender_parameters=
defender_envvars=
defender_type=${defender_type_docker}
upgrade_host=false
OPTIND=1
unset name
optspec="a:c:h:kw:gmzurt:d:f:s:v-:"
while getopts "${optspec}" opt; do
	case "${opt}" in
	-)
		case "${OPTARG}" in
			install-host)
				defender_type=${defender_type_linux_server}
				;;
			install-tas)
				defender_type=${defender_type_tas}
				;;
			install-folder)
				install_folder="${!OPTIND}"; OPTIND=$(( ${OPTIND} + 1 ))
				;;
			install-data-folder)
				install_data_folder="${!OPTIND}"; OPTIND=$(( ${OPTIND} + 1 ))
				;;
			ws-port)
				ws_port="${!OPTIND}"; OPTIND=$(( ${OPTIND} + 1 ))
				;;
			upgrade-host)
				defender_type=${defender_type_linux_server}
				upgrade_host=true
				;;
			prisma-token)
				prisma_token="${!OPTIND}"; OPTIND=$(( ${OPTIND} + 1 ))
				;;
			*)
				if [ "$OPTERR" = 1 ] && [ "${optspec:0:1}" != ":" ]; then
					echo "Unknown option --${OPTARG}" >&2
				fi
				;;
		esac
		;;
	a)  api_addr=${OPTARG}
		;;
	c)  console_cn=${OPTARG}
		;;
	d)  defender_envvars+=" export DEFENDER_LISTENER_TYPE=${OPTARG} "
		;;
	h)  token=${OPTARG}
		;;
	f)  working_folder=${OPTARG}
		;;
	m)  # Advanced custom compliance enabled
		defender_envvars+=" export HOST_CUSTOM_COMPLIANCE_ENABLED=TRUE "
		;;
	r)  # Registry scanner
		additional_defender_parameters+=" -r "
		;;
	s)  # SAN certificate specification
		san=${OPTARG}
		;;
	z)  additional_defender_parameters+=" -z "
		debug_log_level="true"
		;;
	t)  additional_defender_parameters+=" -t ${OPTARG} "
		;;
	v)  skip_tls_flag=""
		;;
	u)  # Unique hostname enabled
		defender_envvars+=" export CLOUD_HOSTNAME_ENABLED=TRUE "
		;;
	esac
done

if [ -z "${api_addr}" ]; then
	api_addr="https://192.168.21.136:8083"
fi
if [ -z "${token}" ]; then
	token="Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyIjoiYWRtaW4iLCJyb2xlIjoiYWRtaW4iLCJncm91cHMiOm51bGwsInJvbGVQZXJtcyI6W1syNTUsMjU1LDI1NSwyNTUsMjU1LDEyNywwXSxbMjU1LDI1NSwyNTUsMjU1LDI1NSwxMjcsMF1dLCJzZXNzaW9uVGltZW91dFNlYyI6MTgwMCwiZXhwIjoxNjMyNzEzNjI2LCJpc3MiOiJ0d2lzdGxvY2sifQ.oixjmcB44AAg5iSRJD76ECK0RK4FNWwqoSmFHtQDMwY"
fi
if [ -z "${console_cn}" ]; then
	console_cn="192.168.21.136"
fi
if [ -z "${ws_port}" ]; then
	ws_port="8084"
fi
# Set the auth header explicitly as in SaaS twistcli pass the Prisma Cloud token instead of compute token
if [ -z "${prisma_token}" ]; then
  authorization_header="authorization: ${token}"
else
  authorization_header="x-redlock-auth: ${prisma_token}"
fi

mkdir -p ${working_folder}
# Move to install folder to support distribution that does not allow
# executing binaries
pushd ${working_folder} > /dev/null

print_debug "DEFENDER_TYPE: ${defender_type}"
print_debug "CONSOLE_CN: ${console_cn}"
print_debug "DEFENDER_CN: ${DEFENDER_CN}"
print_debug "API address: ${api_addr}"
print_debug "Working folder: ${working_folder}"
print_debug "SAN: ${san}"
api_addr+="/api/v1"
util_path="${api_addr}/util"
curl="curl --show-error --fail -sSL ${skip_tls_flag}"

print_info "Downloading and extracting Defender image"
if [[ "${defender_type}" == "${defender_type_linux_server}" ]]; then
	if ! ${upgrade_host} && command_exists docker; then
		defender_exists=$(docker ps -q -f name=twistlock_defender)
		if [ -n "${defender_exists}" ]; then
			exit_now "Defender for Docker is already installed. Please decommission in order to continue"
		fi
	fi

	if [ -n "${install_folder}" ]; then
		additional_defender_parameters+=" --install-folder ${install_folder} "
	fi
	# TODO #21995: Pass data folder in all deployment types
	if [ -n "${install_data_folder}" ]; then
		additional_defender_parameters+=" --install-data-folder ${install_data_folder} "
	fi
	image_name="twistlock_defender_server.tar.gz"
elif [[ "${defender_type}" == "${defender_type_tas}" ]]; then
	image_name="twistlock_defender_server.tar.gz"
else
	image_name="twistlock_defender.tar.gz"
fi

if [ -n "${ws_port}" ]; then
	additional_defender_parameters+=" --ws-port ${ws_port} "
fi

if ! ${upgrade_host}; then
	${curl} --header "${authorization_header}" ${api_addr}/images/${image_name} -o ${image_name} > ${install_log} 2>&1
	exit_on_failure $? "Failed to download Defender image from Console"
        print_info "Downloading Twistlock scripts"
        ${curl} --header "${authorization_header}" ${api_addr}/scripts/twistlock.sh -o twistlock.sh > ${install_log} 2>&1
        exit_on_failure $? "Failed downloading twistlock.sh"
        ${curl} --header "${authorization_header}" ${api_addr}/scripts/twistlock.cfg -o twistlock.cfg > ${install_log} 2>&1
        exit_on_failure $? "Failed downloading twistlock.cfg"
        ${curl} --header "${authorization_header}" ${api_addr}/certs/service-parameter -o service-parameter > ${install_log} 2>&1
        exit_on_failure $? "Failed downloading service-parameter"
	# Download certificates only on clean install
	print_debug "Downloading Twistlock certificates"
	download_certs
fi

# Read console configuration
source twistlock.cfg

print_info "Running twistlock.sh and installing Defender (skipping EULA)"
${defender_envvars}; cat twistlock.sh | bash -s -- ${additional_defender_parameters} -s -a "${console_cn}" -b "eyJzZWNyZXRzIjp7fSwiZ2xvYmFsUHJveHlPcHQiOnsiaHR0cFByb3h5IjoiIiwibm9Qcm94eSI6IiIsImNhIjoiIiwidXNlciI6IiIsInBhc3N3b3JkIjp7ImVuY3J5cHRlZCI6IiJ9fSwibWljcm9zZWdDb21wYXRpYmxlIjpmYWxzZX0=" "${defender_type}"
exit_on_failure $? "Failed to run twistlock.sh" true

print_info "Installation completed, deleting temporary files"
rm "${working_folder}"/* && rmdir "${working_folder}"    # don't delete recursively to minimize potential data-loss
popd > /dev/null

