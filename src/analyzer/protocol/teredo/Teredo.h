#pragma once

#include "analyzer/Analyzer.h"
#include "NetVar.h"
#include "Reporter.h"

namespace analyzer { namespace teredo {

class Teredo_Analyzer : public analyzer::Analyzer {
public:
	explicit Teredo_Analyzer(Connection* conn) : Analyzer("TEREDO", conn)
		{}

	~Teredo_Analyzer() override
		{}

	void Done() override;

	void DeliverPacket(int len, const u_char* data, bool orig,
					uint64_t seq, const IP_Hdr* ip, int caplen) override;

	static analyzer::Analyzer* Instantiate(Connection* conn)
		{ return new Teredo_Analyzer(conn); }

	/**
	 * Emits a weird only if the analyzer has previously been able to
	 * decapsulate a Teredo packet in both directions or if *force* param is
	 * set, since otherwise the weirds could happen frequently enough to be less
	 * than helpful.  The *force* param is meant for cases where just one side
	 * has a valid encapsulation and so the weird would be informative.
	 */
	void Weird(const char* name, bool force = false) const
		{
		if ( ProtocolConfirmed() || force )
			reporter->Weird(Conn(), name);
		}

	/**
	 * If the delayed confirmation option is set, then a valid encapsulation
	 * seen from both end points is required before confirming.
	 */
	void Confirm()
		{
		if ( ! BifConst::Tunnel::delay_teredo_confirmation ||
		     ( valid_orig && valid_resp ) )
			ProtocolConfirmation();
		}

protected:
	bool valid_orig = false;
	bool valid_resp = false;
};

class TeredoEncapsulation {
public:
	explicit TeredoEncapsulation(const Teredo_Analyzer* ta) : analyzer(ta)
		{}

	~TeredoEncapsulation();

	/**
	 * Returns whether input data parsed as a valid Teredo encapsulation type.
	 * If it was valid, the len argument is decremented appropriately.
	 */
	bool Parse(const u_char* data, int& len)
		{ return DoParse(data, len, false, false); }

	const u_char* InnerIP() const
		{ return inner_ip; }

	const u_char* OriginIndication() const
		{ return origin_indication; }

	const u_char* Authentication() const
		{ return auth; }

	RecordVal* BuildVal(const IP_Hdr* inner) const;

protected:
	bool DoParse(const u_char* data, int& len, bool found_orig, bool found_au);

	void Weird(const char* name) const
		{ analyzer->Weird(name); }

	u_char* inner_ip = nullptr;
	u_char* origin_indication = nullptr;
	u_char* auth = nullptr;
	const Teredo_Analyzer* analyzer;
};

} } // namespace analyzer::*
