import * as yup from 'yup'

export const phoneNumberSchema = yup.string()
  .matches(/^\+?[1-9]\d{1,14}$/, 'Invalid phone number format')
  .required('Phone number is required')

export const bulkCallSchema = yup.object().shape({
  numbers: yup.string()
    .required('Phone numbers are required')
    .test('valid-numbers', 'Invalid phone numbers found', function(value) {
      if (!value) return false
      const numbers = value.split('\n').map(n => n.trim()).filter(Boolean)
      return numbers.every(num => phoneNumberSchema.isValidSync(num))
    }),
  systemPrompt: yup.string()
    .required('System prompt is required')
    .min(10, 'System prompt must be at least 10 characters')
    .max(2000, 'System prompt must not exceed 2000 characters')
})

export const dateRangeSchema = yup.object().shape({
  start: yup.date().max(yup.ref('end'), 'Start date must be before end date'),
  end: yup.date().min(yup.ref('start'), 'End date must be after start date')
})

export const validatePhoneNumbers = (numbers) => {
  const errors = []
  const validNumbers = []

  numbers.forEach((number, index) => {
    try {
      phoneNumberSchema.validateSync(number)
      validNumbers.push(number)
    } catch (error) {
      errors.push({ index, number, error: error.message })
    }
  })

  return { validNumbers, errors }
}
