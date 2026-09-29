export type PaymentIntent = {
  ref: string;
  product_id: string;
  product_name: string;
  amount: number;
  expected_phone: string;
  method: "Bankily" | "Masrvi" | "Sedad" | "BIM" | "Click" | "BCIPAY";
  status: "pending" | "paid" | "expired" | "cancelled";
  mode: "test" | "live";
  matched_tier: 1 | 2 | 3 | null;
  actual_sender_phone: string | null;
  sms_received: string | null;
  customer_email: string | null;
  invoice_sent_at: string | null;
  created_at: string;
  expires_at: string;
  paid_at: string | null;
};

export type OrphanSms = {
  id: string;
  raw_body: string;
  parsed_amount: number | null;
  parsed_phone: string | null;
  parsed_method: string | null;
  received_at: string;
  resolved_at: string | null;
  resolved_to_ref: string | null;
  resolved_by: string | null;
};

export type Product = {
  id: string;
  name: string;
  description: string | null;
  price: number;
  active: boolean;
  created_at: string;
  updated_at: string;
};
