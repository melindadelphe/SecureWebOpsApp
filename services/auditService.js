import { createClient } from '@supabase/supabase-js';

const supabase = createClient(process.env.SUPABASE_URL, process.env.SUPABASE_SERVICE_KEY);

export const logEvent = async (eventData) => {
    const { action, fileName, user, status, ip } = eventData;
    
    const { error } = await supabase
        .from('audit_logs')
        .insert([{ 
            action_type: action, 
            file_name: fileName, 
            performed_by: user || 'SYSTEM_AUTH', 
            status: status,
            ip_address: ip
        }]);

    if (error) console.error("FAILED TO LOG AUDIT:", error);
};